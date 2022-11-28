/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get (1, 1);
	swap_table = bitmap_create (disk_size (swap_disk) / (PGSIZE / DISK_SECTOR_SIZE));
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->idx = -1;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	// swap disk에서 idx부분을 읽어 frame에 기록
	size_t idx = anon_page->idx;
	if (idx == -1 || !bitmap_test (swap_table, idx)) {
		printf ("\nanon_swap_in: failed\n\n");
		return false;
	}
	for (size_t i = 0; i < (PGSIZE / DISK_SECTOR_SIZE); i++) {
		disk_read (swap_disk, idx * (PGSIZE / DISK_SECTOR_SIZE) + i, kva + DISK_SECTOR_SIZE * i);
	}
	bitmap_set (swap_table, idx, false);
	// printf ("\nanon_swap_in: idx[%d] complete\n\n", anon_page->idx);
	anon_page->idx = -1;
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	// frame 내용을 비어있는 swap disk에 기록
	size_t idx = bitmap_scan (swap_table, 0, 1, false);
	if (idx == BITMAP_ERROR) {
		printf ("\nanon_swap_out: failed\n\n");
		return false;
	}
	for (size_t i = 0; i < (PGSIZE / DISK_SECTOR_SIZE); i++) {
		disk_write (swap_disk, idx * (PGSIZE / DISK_SECTOR_SIZE) + i, page->va + DISK_SECTOR_SIZE * i);
	}
	bitmap_set (swap_table, idx, true);
	pml4_clear_page (thread_current ()->pml4, page->va);
	anon_page->idx = idx;
	// printf ("\nanon_swap_out: idx[%d] complete\n\n", idx);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
