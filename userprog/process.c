#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy, *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	strtok_r (file_name, " ", &save_ptr);
	// printf ("file_name: %s\n", file_name);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	// child가 생성에 실패하거나 복제에 실패하면 TID_ERROR를 return
	/* Clone current thread to new thread.*/
	struct thread *curr = thread_current ();
	tid_t child_tid = thread_create (name, PRI_DEFAULT, __do_fork, curr);
	if (child_tid == TID_ERROR) {
		return TID_ERROR;
	}
	struct thread *child = process_get_child (child_tid);
	ASSERT (child);
	// child의 fork가 완료될 때까지 대기
	sema_down (&child->sema_for_fork);
	if (child->exit_status == -1) {
		return TID_ERROR;
	}
	return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	// printf("va? %x\n", va);
	if (is_kernel_vaddr(va)) {
		// printf("kernel page\n");
		return true;
	}
	// printf("user page\n");
	
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (!parent_page) {
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (!newpage) {
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy (newpage, parent_page, PGSIZE);
	writable = is_writable (pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		// printf ("failed to insert page\n");
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	// printf ("process__do_fork: (%s)fork child(%s)\n", parent->name, current->name);
	struct intr_frame *parent_if = parent->syscall_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		// printf("error in __do_fork's pml4_create\n");
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if (parent->fd_ptr == (3 * PGSIZE / sizeof(struct file *))) {
		goto error;
	}
	current->fd_table[0] = parent->fd_table[0];
	current->fd_table[1] = parent->fd_table[1];
	for (int i = 2; i < parent->fd_ptr; i++) {
		current->fd_table[i] = file_duplicate(parent->fd_table[i]);
		if (!current->fd_table[i]) {
			goto error;
		}
	}
	current->fd_ptr = parent->fd_ptr;
	// 자식 프로세스의 return 값은 0
	if_.R.rax = 0;
	process_init ();
	// fork가 완료되었으므로 대기 중인 부모 프로세스를 깨움
	sema_up (&current->sema_for_fork);

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	// printf("error in __do_fork\n");
	// fork가 실패해도 대기 중인 부모 프로세스를 깨움
	sema_up (&current->sema_for_fork);
	exit (-1);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	#ifdef VM
	supplemental_page_table_init (&thread_current()->spt);
	#endif

	/* And then load the binary */
	// printf ("process_exec: (%s)[%d] load (%s)...\n", thread_current ()->name, thread_current ()->tid, file_name);
	success = load (file_name, &_if);
	// printf ("process_exec: (%s)[%d] load (%s) complete\n", thread_current ()->name, thread_current ()->tid, file_name);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// printf ("process_wait: (%s)[%d] wait for child[%d] in [%d]children\n", thread_current ()->name, thread_current ()->tid, child_tid, list_size (&thread_current ()->children));
	struct thread *child = process_get_child(child_tid);
	if (!child) {
		return -1;
	}
	// printf ("process_wait: (%s)[%d] wait child(%s)[%d]...\n", thread_current ()->name, thread_current ()->tid, child->name, child->tid);
	// printf ("process_wait: (%s)[%d]'s sema_for_wait down\n", child->name, child->tid);
	// 자식 프로세스가 종료 될 때까지 대기
	sema_down (&child->sema_for_wait);
	int ret = child->exit_status;
	process_remove_child(child);
	// 정상적으로 자식프로세스의 exit status를 전달받으면 종료 대기 중인 자식 프로세스를 깨움
	sema_up (&child->sema_for_exit);
	// printf("process_wait: (%s)[%d]'s sema_for_exit up\n", child->name, child->tid);
	// printf ("process(%s)[%d] wait process(%s)[%d] complete\n", thread_current ()->name, thread_current ()->tid, child->name, child->tid);
	return ret;
	
	// while(true);
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	// printf("process_exit: loop start\n");
	// STDIN과 STDOUT 제외하고 열려있는 모든 파일 디스크립터를 모두 닫음
	while (curr->fd_ptr > 2) {
		process_close_file (curr->fd_ptr - 1);
	}
	// printf("process_exit: loop end\n");
	// 할당받은 파일 디스크립터 테이블 free
	// palloc_free_page (curr->fd_table);
	palloc_free_multiple (curr->fd_table, 3);
	// load 때 열었던 file 닫음
	file_close (curr->executing);
	// 자식의 종료를 기다리는 부모 프로세스를 깨움
	process_cleanup ();
	sema_up (&curr->sema_for_wait);
	// printf("process_exit: (%s)[%d]'s sema_for_exit down\n", thread_current ()->name, thread_current ()->tid);
	// 부모 프로세스가 정상적으로 exit status를 전달 받을 때까지 대기
	sema_down (&curr->sema_for_exit);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	char *save_ptr;
	char *token;
	int argc = 0;
	char **argv;
	uintptr_t **argv_addr;

	argv = palloc_get_page (PAL_USER | PAL_ZERO);
	argv_addr = palloc_get_page (PAL_USER | PAL_ZERO);

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	// 받은 file_name에서 task에 해당하는 첫 번째 argument 저장
	// printf ("file_name: %s\n", file_name);
	ASSERT (strtok_r(file_name, " ", &save_ptr));
	// printf ("file_name: %s\n", file_name);
	argv[0] = file_name;
	// printf ("argv[0]: %s\n", *argv);
	// printf ("save_ptr: %s\n", save_ptr);

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
	// 실행 중인 파일에 write 할 수 없게 설정
	file_deny_write (file);
	t->executing = file;

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	// 받은 명령어를 토큰화해서 리스트로 저장
	while(token) {
		token = strtok_r(NULL, " ", &save_ptr);
		argc++;
		argv[argc] = token;
	}
	// printf ("argc: %d\n", argc);
	// printf ("rsp: %x\n", if_->rsp);
	// 스택은 거꾸로 자람에 유의하며 토큰화된 arguments를 스택에 push
	for(int j = argc - 1; j > -1; j--) {
		if_->rsp -= strlen(argv[j]) + 1;
		memcpy (if_->rsp, argv[j], strlen(argv[j]) + 1);
		memcpy (&argv_addr[j] , &if_->rsp, sizeof(uintptr_t));
		// printf ("argv[%d]: %s\n", j, argv[j]);
		// printf ("argv_addr[%d]: %x\n", j, argv_addr[j]);
	}
	// word-align
	if_->rsp -= if_->rsp % 8;
	memset (if_->rsp, 0, sizeof(uint8_t) * (if_->rsp % 8));
	// 이전의 넣은 arguements의 주소를 스택에 push 이 때 마지막 NULL도 포함
	if_->rsp -= 8;
	memset (if_->rsp, 0, sizeof(uintptr_t));
	for(int j = argc - 1; j > -1; j--) {
		if_->rsp -= 8;
		memcpy (if_->rsp, &argv_addr[j], sizeof(uintptr_t));
	}
	// rdi와 rsi에 각각 argc와 argv[0]의 주소값 저장
	if_->R.rdi = argc;
	// printf ("rdi: %x\n", if_->R.rdi);
	if_->R.rsi = if_->rsp;
	// printf ("rsi: %x\n", if_->R.rsi);
	// fake return address까지 push
	if_->rsp -= 8;
	memset (if_->rsp, 0, sizeof(uintptr_t));

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// printf ("process_load: file_close[%x]\n", file);
	// file_close (file);
	palloc_free_page (argv);
	palloc_free_page (argv_addr);
	// hex_dump (if_->rsp, if_->rsp, USER_STACK - if_->rsp, true);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

struct thread *
process_get_child (tid_t pid) {
	// pid로 자식 프로세스 검색 후 해당 프로세스가 있다면 해당 프로세스를, 없다면 NULL을 반환
	struct thread *curr = thread_current ();
	if(list_empty (&curr->children))
		return NULL;
	// printf ("process_get_child: [%d] get child[%d]\n", curr->tid, pid);
	struct list_elem *e = list_begin (&curr->children);
	while (e != list_end (&curr->children)) {
		struct thread *t = list_entry (e, struct thread, c_elem);
		// printf ("child[%d]: %s\n", t->tid, t->name);
		if (t->tid == pid) {
			// printf ("Get child\n");
			return t;
		}
		else {
			e = list_next(e);
		}
	}
	return NULL;
}

void
process_remove_child (struct thread *child) {
	// pid로 자식 프로세스 검색 후 해당 프로세스가 있다면 자식 프로세스 리스트에서 제거
	struct thread *curr = thread_current ();
	// printf("process_remove_child: (%s) want to remove child(%s)\n", curr->name, child->name);
	ASSERT(!list_empty (&curr->children));
	struct list_elem *e = list_begin (&curr->children);
	while (e != list_end (&curr->children)) {
		struct thread *t = list_entry (e, struct thread, c_elem);
		if (t->tid == child->tid) {
			// printf ("Child removed\n");
			e = list_remove (e);
			break;
		}
		else {
			e = list_next(e);
		}
	}
}

int
process_add_file (struct file *f) {
	// 해당 파일을 파일 디스크럽터 테이블에 추가 후 fd 반환, 더 이상 파일을 추가할 수 없다면 -1 반환
	if (!f) {
		return -1;
	}
	struct thread *curr = thread_current ();
	if (curr->fd_ptr == (3 * PGSIZE / sizeof(struct file *))) {
		// printf ("process_add_file: fd_table full\n");
		return -1;
	}
	int fd = curr->fd_ptr;
	curr->fd_table[fd] = f;
	curr->fd_ptr++;
	return fd;
}

struct file *
process_get_file (int fd) {
	// 파일 디스크럽터 테이블에서 해당 fd를 찾아 있다면 해당 파일을, 없다면 NULL을 반환 
	struct thread *curr = thread_current ();
	if (fd < 0 || fd >= curr->fd_ptr) {
		// printf("bad_fd[%d] with fd_ptr[%d]\n", fd, curr->fd_ptr);
		return NULL;
	}
	// printf("fd[%d] = file[%x]\n", fd, curr->fd_table[fd]);
	
	return curr->fd_table[fd];
}

void
process_close_file(int fd) {
	// 파일 디스크럽터 테이블에서 해당 fd를 찾아 있다면 해당 파일을 닫고 테이블에서 제거 후 테이블 포인터 조정
	struct thread *curr = thread_current ();
	// printf ("process_close_file: (%s) fd_ptr[%d]\n", curr->name, curr->fd_ptr);
	struct file *f = process_get_file (fd);
	if (f) {
		for (int i = fd; i < curr->fd_ptr - 1; i++) {
			curr->fd_table[i] = curr->fd_table[i + 1];
		}
		curr->fd_ptr--;
		curr->fd_table[curr->fd_ptr] = NULL;
		// printf ("process_close_file: file_close[%x]\n", f);
		file_close (f);
	}
}


#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf ("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct parameters *params = aux;
	struct file *file = params->file;
	off_t ofs = params->ofs;
	size_t page_read_bytes = params->page_read_bytes;
	size_t page_zero_bytes = PGSIZE - page_read_bytes;
	// free (params);
	// printf ("\nlazy_load_segment: params = (file[%x], ofs[%d], page_read_bytes[%d])\n\n", file, ofs, page_read_bytes);
	file_seek (file, ofs);
	if (file_read (file, page->frame->kva, page_read_bytes) != (int) page_read_bytes) {
		return false;
	}
	memset (page->frame->kva + page_read_bytes, 0, page_zero_bytes);
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// printf ("\nload_segment: loop\n\n");
		struct parameters *params = malloc (sizeof (struct parameters));
		params->file = file;
		params->ofs = ofs;
		params->page_read_bytes = page_read_bytes;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, params)) {
			printf ("\nload_segment: vm_alloc_page_with_initializer failed\n\n");
			free (params);
			return false;
		}
		ofs += page_read_bytes;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	if(vm_alloc_page (VM_ANON | VM_MARKER_STACK, stack_bottom, true)) {
		if (vm_claim_page (stack_bottom)) {
			success = true;
			if_->rsp = USER_STACK;
			thread_current ()->stack_bottom = stack_bottom;
		}
	}
	// printf ("\nsetup_stack: complete[%s]\n\n", success ? "true" : "false");
	return success;
}
#endif /* VM */
