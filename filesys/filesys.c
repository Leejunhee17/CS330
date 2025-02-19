#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#ifdef EFILESYS
#include "filesys/fat.h"
#include "threads/thread.h"
#endif

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();

	thread_current ()->cwd = dir_open_root ();
	// printf ("@@@ filesys_init: thread = %s, cwd = %p\n", thread_current ()->name, thread_current ()->cwd);
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) {
	ASSERT (strcmp (name, ""));
	disk_sector_t inode_sector = 0;
#ifdef EFILESYS
	char *file_name;
	struct dir *dir = dir_open_from_path (name, &file_name);
	
	cluster_t inode_clst = fat_create_chain (0);
	inode_sector = cluster_to_sector (inode_clst);
	// printf ("@@@ filesys_create: name = %s, inode_clst = %d, sector = %d\n", name, inode_clst, inode_sector);
	bool success = (dir != NULL
			&& inode_clst != 0
			&& inode_create (inode_sector, initial_size, is_dir)
			&& dir_add (dir, file_name, inode_sector));

	if (is_dir) {
		struct dir *new_dir = dir_open (inode_open (inode_sector));
		dir_add (new_dir, ".", inode_sector);
		dir_add (new_dir, "..", inode_get_inumber (dir_get_inode (dir)));
		dir_close (new_dir);
	}

	dir_close (dir);
	
	if (!success && inode_clst != 0)
		fat_remove_chain (inode_clst, 0); 
#else
	struct dir *dir = dir_open_root ();
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size, false)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
#endif
  // printf ("@@@ filesys_create: name = %s, file_name = %s, %s\n", name, file_name, success ? "success" : "fail");
	return success;
}

bool
symlink_create (const char *name, const char *target) {
	ASSERT (strcmp (name, ""));
	ASSERT (strcmp (target, ""));
	disk_sector_t inode_sector = 0;
	char *file_name;
	struct dir *dir = dir_open_from_path (name, &file_name);
	
	cluster_t inode_clst = fat_create_chain (0);
	inode_sector = cluster_to_sector (inode_clst);
	bool success = (dir != NULL
			&& inode_clst != 0
			&& inode_create (inode_sector, strlen (target), false)
			&& dir_add (dir, file_name, inode_sector));

	dir_close (dir);

	if (!success && inode_clst != 0)
		fat_remove_chain (inode_clst, 0); 

	inode_set_symlink (inode_open (inode_sector), target);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	ASSERT (strcmp (name, ""));
	if (!strcmp (name, "/")) {
		return file_open (inode_open (cluster_to_sector (ROOT_DIR_CLUSTER)));
	}

	char *file_name;
	struct dir *dir = dir_open_from_path (name, &file_name);
	
	struct inode *inode = NULL;

	if (dir != NULL) {
		if (dir_lookup (dir, file_name, &inode)) {
			dir_close (dir);

			if (inode_is_symlink (inode)) {
				return filesys_open (inode_get_symlink_target (inode));
			} else {
				return file_open (inode);
			}
		}

		dir_close (dir);
	}
	// printf ("@@@ filesys_open: name = %s, file_name = %s, inode = %p\n", name, file_name, inode);

	return NULL;
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	ASSERT (strcmp (name, ""));
	bool success = false;
	char *file_name;
	struct dir *parent = dir_open_from_path (name, &file_name);
	// printf ("@@@ filesys_remove: name = %s, file_name = %s\n", name, file_name);
	if (parent == NULL)
		return success;
	
	struct inode *inode = NULL;
	dir_lookup (parent, file_name, &inode);
	if (inode_is_dir (inode)) {
		struct dir *child = dir_open (inode);
		char sub[NAME_MAX + 1];
		if (dir_tell (child) == 0) {
			dir_readdir (child, sub);
			ASSERT (!strcmp (sub, "."));
			dir_readdir (child, sub);
			ASSERT (!strcmp (sub, ".."));
		}
		if (!dir_readdir (child, sub)) {
			success = dir_remove (child, ".") && dir_remove (child, "..") && dir_remove (parent, file_name);
		}
		dir_close (child);
	} else {
		success = dir_remove (parent, file_name);
	}
	dir_close (parent);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	disk_sector_t root_sector = cluster_to_sector (ROOT_DIR_CLUSTER);
	if (!dir_create (root_sector, 0))
		PANIC ("root directory creation failed");
	struct dir *dir = dir_open_root ();
	dir_add (dir, ".", root_sector);
	dir_add (dir, "..", root_sector);
	dir_close (dir);
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
