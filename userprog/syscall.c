#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include <filesys/filesys.h>
#include "userprog/process.h"
#include "threads/palloc.h"
#ifdef VM
#include "vm/vm.h"
#endif
#ifdef EFILESYS
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#endif

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address (void *addr);
#ifdef VM
void check_buffer (void *buffer, unsigned length, bool is_write);
#endif

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init (& filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// printf ("f->R.rax: %llx\n", f->R.rax);
	// printf ("f->R.rdi %llx\n", f->R.rdi);
	// printf ("f->R.rsi: %llx\n", f->R.rsi);
	// printf ("f->R.rdx: %llx\n", f->R.rdx);
	check_address (f->rsp);
	// process.c의 process_fork에서 사용할 인터럽트 프레임 저장
	thread_current ()->syscall_if = f;
#ifdef VM
	thread_current ()->rsp = f->rsp;
#endif
	// exit (-1);

	switch(f->R.rax) {
		case SYS_HALT:
			halt ();
			break;
		case SYS_EXIT:
			exit (f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork (f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec (f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait (f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create (f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove (f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open (f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize (f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek (f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell (f->R.rdi);
			break;
		case SYS_CLOSE:
			close (f->R.rdi);
			break;
#ifdef VM
		case SYS_MMAP:
			f->R.rax = mmap (f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap (f->R.rdi);
			break;
#endif
#ifdef EFILESYS
		case SYS_CHDIR:
			f->R.rax = chdir (f->R.rdi);
			break;
		case SYS_MKDIR:
			f->R.rax = mkdir (f->R.rdi);
			break;
		case SYS_READDIR:
      f->R.rax = readdir (f->R.rdi, f->R.rsi);
			break;
		case SYS_ISDIR:
			f->R.rax = isdir (f->R.rdi);
			break;
		case SYS_INUMBER:
			f->R.rax = inumber (f->R.rdi);
			break;
		case SYS_SYMLINK:
			f->R.rax = symlink (f->R.rdi, f->R.rsi);
			break;
	#endif
		default:
			// printf ("default\n");
			exit (-1);
	}
}

void
check_address (void *addr) {
	// 잘못된 주소를 참조 시 프로세스 종료 ex) 널 포인터, 커널 영역 침범, 매핑 되지 않은 유저 영역
	// printf ("check_address: addr[%x]\n", addr);
	if (!addr) {
		// printf ("NULL pointer\n");
		exit (-1);
	}
	if (is_kernel_vaddr(addr)) {
		// printf ("Over KERN_BASE\n");
		exit (-1);
	}
#ifdef VM
	if (spt_find_page (&thread_current ()->spt, addr) == NULL) {
		// printf ("Unallocated addr\n");
		exit (-1);
	}
#else
	if (!pml4_get_page (thread_current ()->pml4, addr)) {
		// printf ("Unmapped\n");
		exit (-1);
	}
#endif
}

#ifdef VM
void
check_buffer (void *buffer, unsigned length, bool is_write) {
	for (unsigned i = 0; i < length; i++) {
		struct page *p = spt_find_page (&thread_current ()->spt, buffer + i);
		if (is_kernel_vaddr(buffer + i) || p == NULL || (is_write && !p->writable)) {
			exit (-1);
		}
	}
}
#endif

void
halt (void) {
	power_off ();
}

void
exit (int status) {
	// user program만 대한 exit 관련 문구를 출력하기 위해 여기서 printf
	// printf("syscall_exit: called by (%s)[%d]\n", thread_current ()->name, thread_current ()->tid);
	struct thread *curr = thread_current ();
	curr->exit_status = status;
	printf ("%s: exit(%d)\n", curr->name, curr->exit_status);
	thread_exit ();
}

pid_t
fork (const char *thread_name) {
	// printf ("syscall_fork: (%s)[%d] fork child(%s)\n", thread_current ()->name, thread_current ()->tid, thread_name);
	return process_fork (thread_name, 0);
}

int
exec (const char *file) {
	check_address(file);
	struct thread *curr = thread_current ();
	char *fn_copy = palloc_get_page (PAL_USER | PAL_ZERO);
	if (fn_copy == NULL)
		exit (-1);
	strlcpy (fn_copy, file, strlen(file) + 1);
	// printf ("syscall_exec: (%s)[%d] load (%s)...\n", curr->name, curr->tid, fn_copy);
	if (process_exec (fn_copy) == -1)
		// printf ("exec fail\n");
		exit (-1);
}

int
wait (pid_t pid) {
	// printf ("syscall_wait: (%s)[%d] wait(%d) in [%d]children\n", thread_current ()->name, thread_current ()->tid, pid,list_size (&thread_current ()->children));
	return process_wait (pid);
}

bool
create (const char *file, unsigned initial_size) {
	check_address (file);
	// printf("@@@ create: thread(%s) create file(%s, %d)\n", thread_current ()->name, file, initial_size);
	lock_acquire (&filesys_lock);
	bool ret = filesys_create (file, initial_size, false);
	
	lock_release (&filesys_lock);
	return ret;
}

bool
remove (const char *file) {
	check_address (file);
	// printf("syscall_remove: (%s)[%d] remove [%x]\n", thread_current ()->name, thread_current ()->tid, file);
	lock_acquire (&filesys_lock);
	bool ret = filesys_remove (file);
	lock_release (&filesys_lock);
	return ret;
}

int
open (const char *file) {
	check_address (file);
	lock_acquire (&filesys_lock);
	struct file *f = filesys_open (file);
	lock_release (&filesys_lock);
  if (f == NULL) {
    // printf ("@@@ open: file = %s, fail\n", file);
    return -1;
  }
	int fd = process_add_file(f);
	if (fd == -1) {
		// printf ("@@@ open: fd = %d, fail\n", fd);
		file_close (f);
	}
	printf ("@@@ open: thread = %s file = %s, fd = %d\n", thread_current ()->name, file, fd);
	return fd;
}

int
filesize (int fd) {
	struct file *f = process_get_file (fd);
	if (!f) {
		return -1;
	}
	int ret = file_length (f);
	return ret;
}

int
read (int fd, void *buffer, unsigned length) {
	check_address (buffer);
#ifdef VM
	check_buffer (buffer, length, true);
#endif
	// printf ("\nprocess(%s)[%d] call read\n\n", thread_current ()->name, thread_current ()->tid);
	int ret = 0;
	if (fd == 0) {
		// printf ("STDIN\n");
		void *ptr = buffer;
		while (ret < length) {
			uint8_t c = input_getc ();
			memset(ptr, c, sizeof (uint8_t));
			if (c == '\0') {
				break;
			}
			ret++;
			ptr += sizeof (uint8_t);
		}
		return ret;
	}
	else {
		struct file *f = process_get_file(fd);
		if (!f) {
			return -1;
		}
		lock_acquire (&filesys_lock);
		ret = file_read (f, buffer, length);
		lock_release (&filesys_lock);
		return ret;
	}
}

int
write (int fd, const void *buffer, unsigned length) {
	check_address (buffer);
#ifdef VM
	check_buffer (buffer, length, false);
#endif
	// printf ("sysacll_write: (%s)[%d] call write on fd[%d] with buffer[%p]\n", 
	// 	thread_current ()->name, thread_current ()->tid, fd, buffer);
	int ret = 0;
	void *ptr = buffer;
	if (fd == 1) {
		// printf ("STDOUT\n");
		while (ret < length) {
			putbuf (ptr, 1);
			ret++;
			ptr++;
		}
		return ret;
	}
	else {
		struct file *f = process_get_file(fd);
		if (!f) {
			return -1;
		}
		if (inode_is_dir (file_get_inode (f))) {
			return -1;
		}
		lock_acquire (&filesys_lock);
		ret = file_write (f, buffer, length);
		lock_release (&filesys_lock);
		return ret;
	}
}

void
seek (int fd, unsigned position) {
	// printf("process(%s)[%d] seek file[%d] in table[%d]\n", thread_current ()->name, thread_current ()->tid, fd, thread_current ()->fd_ptr);
	struct file *f = process_get_file (fd);
	if (f) {
		file_seek(f, position);
	}
}

unsigned
tell (int fd) {
	struct file *f = process_get_file (fd);
	if (!f) {
		return -1;
	}
	off_t ret = file_tell (f);
	return ret;
}

void
close (int fd) {
	process_close_file (fd);
}

#ifdef VM
void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	// printf ("\nmmap: addr[%p], length[%d], addr+length[%p], writable[%s], fd[%d], offset[%d]\n\n",
	// 	addr, length, addr + length, writable ? "true" : "false", fd, offset);
	if (addr == NULL | is_kernel_vaddr (addr) | addr + length == NULL | is_kernel_vaddr (addr + length)) {
		// printf ("\nmmap: addr[%p](is_kernel?[%s]) is not mappable\n\n", 
		// 	addr, is_kernel_vaddr (addr) ? "true" : "false");
		return NULL;
	}
	if (addr != pg_round_down (addr) | offset % PGSIZE != 0) {
		// printf ("\nmmap: addr[%p](align?[%s]) & offset[%d](align?[%s])is not mappable\n\n", 
		// 	addr, addr == pg_round_down (addr) ? "true" : "false", offset, offset % PGSIZE == 0 ? "true" : "false");
		return NULL;
	}
	if (length == 0) {
		// printf ("\nmmap: length[%d] is not mappable\n\n", length);
		return NULL;
	}
	if (fd == 0 || fd == 1) {
		// printf ("\nmmap: fd[%d] is not mappable\n\n", fd);
		return NULL;
	}
	if (spt_find_page(&thread_current()->spt, addr) != NULL) {
		// printf ("\nmmap: addr[%p] is overlapped\n\n", addr);
		return NULL;
	}
	struct file *file = process_get_file (fd);
	if (file == NULL) {
		// printf ("\nmmap: failed to get file by fd[%d]\n\n", fd);
		return NULL;
	}
	if (file_length (file) == 0) {
		// printf ("\nmmap: file[%p] is zero length\n\n", file);
		return NULL;
	}
	return do_mmap (addr, length, writable, file, offset);
}

void
munmap (void *addr) {
	do_munmap (addr);
}
#endif

#ifdef EFILESYS
bool
chdir (const char *dir) {
  printf ("@@@ chdir: dir = %s\n", dir);
	char *dir_name;
	struct dir* directory = dir_open_from_path (dir, &dir_name);

	struct inode *inode;

	if (dir_lookup (directory, dir_name, &inode)) {
		dir = dir_open (inode);
		if (dir != NULL) {
			thread_current ()->cwd = dir;
			return true;
		}
	}

	return false;
}

bool
mkdir (const char *dir) {
  printf ("@@@ chdir: dir = %s\n", dir);
	return filesys_create (dir, 0, true);
}

bool
readdir (int fd, char name[READDIR_MAX_LEN + 1]) {
  struct file *f = process_get_file (fd);
  struct inode *inode = file_get_inode (f);
  bool success = false;
  if (inode_is_dir (inode)) {
    struct dir *dir = dir_open (inode);
		printf ("@@@ readdir: 1st file_tell = %d\n", file_tell (f));
		dir_seek (dir, file_tell (f));
		if (file_tell (f) == 0) {
			dir_readdir (dir, name);
			dir_readdir (dir, name);
		}
    success = dir_readdir (dir, name);
    file_seek (f, dir_tell (dir));
		printf ("@@@ readdir: 2nd file_tell = %d\n", file_tell (f));
    dir_close (dir);
  }
  printf ("@@@ readdir: fd = %d, name = %s, file_tell = %d, %s\n", fd, name, file_tell (f), success ? "success" : "fail");
  return success;
}

bool
isdir (int fd) {
	struct file *f = process_get_file (fd);
	bool success = inode_is_dir (file_get_inode (f));
	printf ("@@@ isdir: fd = %d, %s\n", fd, success ? "success" : "fail");
	return success;
}

int
inumber (int fd) {
	struct file *f = process_get_file (fd);
	if (f == NULL) {
		return -1;
	}
	int ret = inode_get_inumber (file_get_inode (f));
	printf ("@@@ inumber: fd = %d, inumber = %d\n", fd, ret);
	return ret;
}

int
symlink (const char* target, const char* linkpath) {
	char *link_name;
	struct dir* link_dir = dir_open_from_path (linkpath, &link_name);
	dir_add (link_dir, link_name, inode_get_inumber (file_get_inode (filesys_open (target))));
	return 0;
}
#endif
