/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

uint64_t
spt_hash_func (const struct hash_elem *e, void *aux) {
	struct page *p = hash_entry(e, struct page, p_elem);
	return hash_bytes (&p->va, sizeof (p->va));
}

bool
spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	struct page *p1 = hash_entry(a, struct page, p_elem);
	struct page *p2 = hash_entry(b, struct page, p_elem);
	if (p1->va < p2->va) {
		return true;
	}
	return false;
}

void
spt_hash_destruction_func (struct hash_elem *e, void *aux) {
	// printf ("\nspt_hash_destruction_func\n\n");
	struct page *p = hash_entry (e, struct page, p_elem);
	vm_dealloc_page (p);
}

// process.c에서 복사
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}

// process.c에서 복사
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

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init (&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// printf ("\nvm_alloc_page_with_initializer: type[%d] upage[%p]\n\n", type, upage);
		struct page *page = malloc (sizeof (struct page));
		// page type에 맞는 intializer로 alloca 후 spt_hash에 삽입
		if (VM_TYPE (type) == VM_ANON) {
			uninit_new (page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE (type) == VM_FILE) {
			uninit_new (page, upage, init, type, aux, file_backed_initializer);
		}
		else {
			free (page);
			goto err;
		}
		page->writable = writable;
		/* TODO: Insert the page into the spt. */
		return spt_insert_page (spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	// printf ("\nspt_find_page: find va[%p] in hash[%d]\n\n", va, hash_size (&spt->spt_hash));
	struct page *dummy = malloc (sizeof (struct page));
	dummy->va = pg_round_down (va);
	struct hash_elem *e = hash_find (&spt->spt_hash, &dummy->p_elem);
	free (dummy);
	if (e == NULL) {
		// printf ("\nspt_find_page: failed to find va[%p]\n\n", va);
		return NULL;
	}
	page = hash_entry (e, struct page, p_elem);
	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert (&spt->spt_hash, &page->p_elem) == NULL) {
		succ = true;
		// printf ("\nspt_insert_page: insert complete page->va[%p] in thread[%s]'s spt_hash size[%d]\n\n", 
		// 	page->va, thread_current ()->name, hash_size (&spt->spt_hash));
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	// 간단하게 FIFO로 맨 앞의 frame을 victim으로 선정
	struct list_elem *v = list_pop_front (&frame_table);
	victim = list_entry (v, struct frame, f_elem); 
	list_push_back (&frame_table, v);
	// printf ("\nvm_get_victim: victim->kva[%p] in frame_table size[%d]\n\n", victim->kva, list_size (&frame_table));
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	// printf ("\nvm_evict_frame\n\n");
	swap_out (victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	frame = malloc (sizeof (struct frame));
	ASSERT (frame != NULL);
	frame->kva = palloc_get_page (PAL_USER);
	if (frame->kva == NULL) {
		// palloc에 실패하면 frame_table에서 frame 하나 evict
		// PANIC ("todo");
		frame = vm_evict_frame ();
	}
	else {
		// palloc에 성공하면 frame_table에 추가
		list_push_back (&frame_table, &frame->f_elem);
	}
	frame->page = NULL;
	// printf ("\nvm_get_frame: get frame->kva[%p]\n\n", frame->kva);
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// 스택을 페이지 하나만큼 성장
	void *stack_bottom = thread_current ()->stack_bottom - PGSIZE;
	if(vm_alloc_page (VM_ANON | VM_MARKER_STACK, stack_bottom, true)) {
		if (vm_claim_page (stack_bottom)) {
			thread_current ()->stack_bottom = stack_bottom;
		}
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// printf ("Page fault at %p(is_kernel_addr?[%s]): %s error %s page in %s context.\n",
	// 		addr,
	// 		is_kernel_vaddr (addr) ? "true" : "false",
	// 		not_present ? "not present" : "rights violation",
	// 		write ? "writing" : "reading",
	// 		user ? "user" : "kernel");
	if (is_kernel_vaddr (addr) || !not_present) {
		return false;
	}
	if (!vm_claim_page (addr)) {
		// claim에 실패했을 때 스택 관련 문제인지 확인
		// user에서 fault면 받은 인터럽트에서 rsp 추출, kernel이면 thread에 저장된 rsp 사용
		void *rsp = user ? f->rsp : thread_current ()->rsp;
		if (addr < USER_STACK && addr > USER_STACK - 0x1000000) {
			if (addr >= rsp - 8) {
				vm_stack_growth (addr);
				return true;
			}
		}
		return false;
	}
	return true;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	// printf ("\nvm_claim_page: claim va[%p]\n\n", va);
	page = spt_find_page (&thread_current ()->spt, va);
	if (page == NULL) {
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(!install_page (page->va, frame->kva, page->writable)) {
		printf ("\nvm_do_claim_page: install_page failed\n\n");
		return false;
	};
	// printf ("\nvm_do_claim_page: install complete page->va[%p] frame->kva[%p] page->writable[%s]\n\n",
	// 	page->va, frame->kva, page->writable ? "true" : "false");
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->spt_hash, spt_hash_func, spt_less_func, NULL);
	// printf ("\nsupplemental_page_table_init\n\n");
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	// printf ("\nsupplemental_page_table_copy: hash_size[%d]\n\n", hash_size (&src->spt_hash));
	// hash안의 page들 순회
	struct hash_iterator i;
	hash_first (&i, &src->spt_hash);
	while (hash_next (&i))
	{
		struct page *src_page = hash_entry (hash_cur (&i), struct page, p_elem);
		enum vm_type src_type = VM_TYPE (src_page->operations->type);
		void *upage = src_page->va;
		bool writable = src_page->writable;
		// printf ("\nsupplemental_page_table_copy: copy page(type[%d], va[%p], writable[%s])\n\n",
		// 	src_type, upage, writable ? "true" : "false");
		// stack page였다면 child thread의 stack도 알맞게 설정
		if (src_page->uninit.type & VM_MARKER_STACK) {
            setup_stack(&thread_current()->tf);
        }
		// uninit이면 parameters를 복사해 새로 allocate with initializer
		else if (src_type == VM_UNINIT) {
			struct parameters *params = malloc (sizeof (struct parameters));
			memcpy (params, src_page->uninit.aux, sizeof (struct parameters));
			if (!vm_alloc_page_with_initializer(src_page->uninit.type, upage, writable, src_page->uninit.init, params)) {
				free (params);
				// printf ("\nsupplemental_page_table_copy: vm_alloc_page_with_initializer failed\n\n");
				return false;
			}
		}
		// anon이나 file이면 단순 allocate 후 claim
		else if (src_type == VM_ANON || src_type == VM_FILE) {
			if (!vm_alloc_page (src_type, upage, writable)) {
				return false;
			}
			if (!vm_claim_page (upage)) {
				return false;
			}
		}
		else {
			printf ("\nvsupplemental_page_table_copy: page type error\n\n");
			return false;
		}
		// intialize가 끝난 anon과 file을 frame의 내용도 복사
		if (src_type == VM_ANON || src_type == VM_FILE) {
			struct page *dst_page = spt_find_page (dst, upage);
			memcpy (dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
		
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// printf ("\nsupplemental_page_table_kill: thread[%s]\n\n", thread_current ()->name);
	struct hash *h = &spt->spt_hash;
	if (!hash_empty (h)) {
		struct hash_iterator i;
		hash_first (&i, h);
		while (hash_next (&i))
		{
			struct page *p = hash_entry (hash_cur (&i), struct page, p_elem);
			if (VM_TYPE (p->operations->type) == VM_FILE) {
				// file page의 경우 spt 정리 시 unmap
				// printf ("\nsupplemental_page_table_kill: p->va[%p]\n\n", p->va);
				do_munmap (p->va);
			}
		}
		hash_destroy (h, spt_hash_destruction_func);
	}
}
