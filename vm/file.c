/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	// printf ("\nfile_backed_swap_in\n\n");
	struct parameters *params = page->uninit.aux;
	struct file *file = params->file;
	off_t ofs = params->ofs;
	size_t page_read_bytes = params->page_read_bytes;
	size_t page_zero_bytes = PGSIZE - page_read_bytes;
	// free (params);
	// printf ("\nlazy_load_segment: params = (file[%x], ofs[%d], page_read_bytes[%d])\n\n", file, ofs, page_read_bytes);
	// 파일을 읽어 frame에 기록
	file_seek (file, ofs);
	if (file_read (file, page->frame->kva, page_read_bytes) != (int) page_read_bytes) {
		return false;
	}
	memset (page->frame->kva + page_read_bytes, 0, page_zero_bytes);
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct parameters *params = page->uninit.aux;
	// printf ("\nfile_backed_swap_out: params(file[%p], ofs[%d], page_read_bytes[%d])\n\n",
	// 	params->file, params->ofs, params->page_read_bytes);
	struct thread *curr = thread_current ();
	// 페이지에 변경된 사항이 있다면 파일에 적용
	if (pml4_is_dirty (curr->pml4, page->va)) {
		file_seek (params->file, params->ofs);
		file_write (params->file, page->va, params->page_read_bytes);
		pml4_set_dirty (curr->pml4, page->va, false);
	}
	pml4_clear_page (curr->pml4, page->va);
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	// printf ("\nfile_backed_destroy: page->va[%p]\n\n", page->va);
	// do_munmap (page->va);
}

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

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	void *upage = addr;
	struct file *new_file = file_reopen (file);
	size_t read_bytes = length > file_length(new_file) ? file_length(new_file) : length;
	size_t zero_bytes = PGSIZE - (read_bytes % PGSIZE);
	// printf ("\ndo_mmap: new_file[%p], addr[%p], length[%d], read_bytes[%d], zero_bytes[%d]\n\n",
	// 	new_file, addr, length, read_bytes, zero_bytes);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// printf ("\nload_segment: loop\n\n");
		struct parameters *params = malloc (sizeof (struct parameters));
		params->file = new_file;
		params->ofs = offset;
		params->page_read_bytes = page_read_bytes;
		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_segment, params)) {
			free (params);
			printf ("\ndo_mmap: vm_alloc_page_with_initializer failed\n\n");
			return NULL;
		}
		offset += page_read_bytes;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	// printf ("\ndo_mmap: complete\n\n");
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread *curr = thread_current ();
	// printf ("\ndo_munmap: thread[%s] addr[%p]\n\n", curr->name, addr);
	while (true) {
		struct page *page = spt_find_page (&curr->spt, addr);
		if (page == NULL) {
			// printf ("\ndo_munmap: loop break\n\n", addr);
			break;
		}
		// addr부터 연속된 page의 pml4을 검사해 변경 사항이 있다면 파일에 적용
		struct parameters *params = (struct parameters *)page->uninit.aux;
		// printf ("\ndo_munmap: params(file[%p], ofs[%p], page_read_bytes[%d])\n\n",
		// 	params->file, params->ofs, params->page_read_bytes);
		if (pml4_is_dirty (curr->pml4, page->va)) {
			// printf ("\ndo_munmap: dirty\n\n");
			file_seek (params->file, params->ofs);
			file_write (params->file, page->va, params->page_read_bytes);
			pml4_set_dirty (curr->pml4, page->va, false);
		}
		pml4_clear_page (curr->pml4, page->va);
		addr += PGSIZE;
	}
	// printf ("\ndo_munmap: complete\n\n");
}
