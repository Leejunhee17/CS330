#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/fat.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	bool is_dir;                        /* True if directory, false otherwise. */
	bool is_symlink;                    /* True if symlink, false otherwise. */
	bool unused[512 - 4 * 3 - 1 * 2];   /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	disk_sector_t sector;               /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	struct inode_disk data;             /* Inode content. */
};

/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);
#ifdef EFILESYS
  // printf ("@@@ byte_to_sector: start = %d, length = %d, pos= %d\n", inode->data.start, inode->data.length, pos);
	cluster_t clst = sector_to_cluster (inode->data.start);
  ASSERT (clst != -1);
  disk_sector_t sectors = pos / DISK_SECTOR_SIZE;
  while (sectors > 0) {
      cluster_t pclst = clst;
			clst = fat_get(clst);
      if (clst == EOChain) {
        clst = pclst;
        break;
      }
			sectors--;
	}
  while (sectors > 0) {
    clst = fat_create_chain (clst);
    ASSERT (clst != 0);
    sectors--;
  }
  ASSERT (sectors == 0);
  // printf ("@@@ byte_to_sector: sector = %d\n",  cluster_to_sector (clst));
  return cluster_to_sector (clst);
#else
  if (pos < inode->data.length) {
		return inode->data.start + pos / DISK_SECTOR_SIZE;
	} else
		return -1;
#endif
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool is_dir) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
#ifdef EFILESYS
		cluster_t clst = fat_create_chain (0);
		if (clst != 0) {
			disk_inode->start = cluster_to_sector (clst);
			disk_inode->is_dir = is_dir;
			disk_inode->is_symlink = false;
      // printf ("@@@ inode_create: disk_write disk_inode(%d, %d) at sector(%d)\n", disk_inode->start, disk_inode->length, sector);
			disk_write (filesys_disk, sector, disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;
				// printf ("@@@ inode_create: disk_write disk_inode(%d, %d) at sector(%d)\n", disk_inode->start, disk_inode->length, cluster_to_sector (clst));
				disk_write (filesys_disk, cluster_to_sector (clst), zeros);
				for (i = 0; i < sectors - 1; i++) {
					clst = fat_create_chain (clst);
					if (clst == 0) {
            printf ("inode_create: fat_create_chain failed\n");
						return success;
					}
					disk_write (filesys_disk, cluster_to_sector (clst), zeros);
				}
			}
      // printf ("@@@ inode_create: start = %d, length = %d\n", disk_inode->start, disk_inode->length);
			success = true;
		}
#else
		if (free_map_allocate (sectors, &disk_inode->start)) {
			disk_write (filesys_disk, sector, disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

				for (i = 0; i < sectors; i++) 
					disk_write (filesys_disk, disk_inode->start + i, zeros); 
			}
			success = true; 
		}
#endif
		free (disk_inode);
	}
  // printf ("@@@ inode_create: sector = %d, success = %s\n", sector, success ? "true" : "false");
	return success;
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	// printf ("@@@@ inode open count! %d -> set 1 \n", inode->sector);
	
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read (filesys_disk, inode->sector, &inode->data);
  // printf ("@@@ inode_open: sector = %d, start = %d, length = %d\n", inode->sector, inode->data.start, inode->data.length);
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL) {
		inode->open_cnt++;
		// printf ("@@@@ inode open count! %d -> set %d (++) \n", inode->sector, inode->open_cnt);
	}
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	// if (inode->removed) {
	// 		fat_remove_chain (sector_to_cluster (inode->sector), 0);
	// 		fat_remove_chain (sector_to_cluster (inode->data.start), 0);
		// printf ("@@@@ yeah~ tell us the reason [%d] cnt: %d \n", inode->sector, inode->open_cnt);
	// }

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		// printf ("@@@ inode_close: inode = %p\n", inode);
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
#ifdef EFILESYS
			// printf ("@@@@ haha %d \n", inode->sector);
			
			fat_remove_chain (sector_to_cluster (inode->sector), 0);
			fat_remove_chain (sector_to_cluster (inode->data.start), 0);
#else
			free_map_release (inode->sector, 1);
			free_map_release (inode->data.start,
					bytes_to_sectors (inode->data.length)); 
#endif
		}

		free (inode); 
	} else {
		// printf ("@@@@ inode open count! %d -> set %d (--) \n", inode->sector, inode->open_cnt);
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
  // printf ("@@@ inode_read_at: start(%d), length(%d), size(%d), offset(%d)\n", 
  //   inode->data.start, inode->data.length, size, offset);
  uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;
    // printf ("@@@ inode_write_at: min_left = %d, inode_left = %d, sector_left = %d\n", min_left, inode_left, sector_left);

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
		} else {
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read (filesys_disk, sector_idx, bounce);
			memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free (bounce);

	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,	off_t offset) {
  // printf ("@@@ inode_write_at: start(%d), length(%d), size(%d), offset(%d)\n", 
  //   inode->data.start, inode->data.length, size, offset);
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

	if (inode->deny_write_cnt)
		return 0;

  if (inode->data.length < offset) {
    inode->data.length = offset;
  }
	while (size > 0) {
		/* Sector to write, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left > 0 && inode_left < sector_left ? inode_left : sector_left;
    // printf ("@@@ inode_write_at: min_left = %d, inode_left = %d, sector_left = %d\n", min_left, inode_left, sector_left);

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;
    // printf ("@@@ inode_write_at: size = %d, chunk_size = %d, sector_idx = %d\n", size, chunk_size, sector_idx);

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Write full sector directly to disk. */
			disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
		} else {
			/* We need a bounce buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left) 
				disk_read (filesys_disk, sector_idx, bounce);
			else
				memset (bounce, 0, DISK_SECTOR_SIZE);
			memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
			disk_write (filesys_disk, sector_idx, bounce); 
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
    if (inode_left <= 0)
      inode->data.length += chunk_size;
    // printf ("@@@ inode_write_at: loop end, size = %d, offset = %d, bytes_written= %d, inode->data.length = %d\n", 
    //   size, offset, bytes_written, inode->data.length);
	}
	free (bounce);
  if (bytes_written > 0) {
    disk_write (filesys_disk, inode->sector, &inode->data);
  }

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
	void
inode_deny_write (struct inode *inode) 
{
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	return inode->data.length;
}

bool
inode_is_dir (const struct inode *inode) {
	return inode->data.is_dir;
}

bool
inode_is_symlink (const struct inode *inode) {
	return inode->data.is_symlink;
}

void
inode_set_symlink (struct inode *inode, const char *target) {
	inode->data.is_symlink = true;
	inode_write_at (inode, target, strlen (target), 0);
}

char *
inode_get_symlink_target (struct inode *inode) {
	char *target = malloc (inode->data.length + 1);
	inode_read_at (inode, target, inode->data.length, 0);
	target[inode->data.length] = '\0';
	
	return target;
}
