#include "vm/page.h"
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/malloc.h"
#include "vm/swap.h"
#include "userprog/syscall.h"
#include "lib/string.h"


/* Destroys a page, which must be in the current process's
   page table.  Used as a callback for hash_destroy(). */
static void
destroy_page (struct hash_elem *p_, void *aux UNUSED)
{
    /* get the current process's page table */
    struct thread *t = thread_current ();
    struct page *p = hash_entry (p_, struct page, elem);

    frame_lock (p);
    if (p->frame != NULL) {
        frame_free (p->frame);
    }

    // /* assert that the page's owner is the current process */
    // ASSERT (p->thread == t);

    // /* remove the page from the current process's page table */
    // hash_delete (&t->pages, &p->elem);

    /* free the page */
    free (p);
}

/* Destroys the current process's page table. */
void
page_exit (void)
{
    struct hash *page_table = thread_current ()->pages;
    /* destroy the current process's page table */
    if (page_table != NULL) {
        hash_destroy (page_table, destroy_page);
    }
}

/* Returns the page containing the given virtual ADDRESS,
   or a null pointer if no such page exists.
   Allocates stack pages as necessary. */
struct page *
page_for_addr (const void *address)
{
    /* do preliminary checking on provided virtual address */
    if (address == NULL || !is_user_vaddr (address))
        return NULL;

    /* extract current process's page */
    struct thread *t = thread_current ();
    struct page p;  /* allocate page struct not page pointer -- Roy tip in OH
                        - easier for hash_find() function */
    // struct page *p;
    struct hash_elem *e;

    /* set the page's virtual address to the given address */
    p.vaddr = (void *) pg_round_down (address);
    // p.vaddr = (void *) pg_round_down (address);

    /* find the page in the current process's page table */
    e = hash_find (t->pages, &p.elem);
    // e = hash_find (t->pages, &p->elem);

    /* if the page is in the current process's page table */
    if (e != NULL) {
        // printf("HITTING PAGE IN PAGE_FOR_ADDR\n\n");
        return hash_entry (e, struct page, elem);
    }

    /* otherwise, allocate a stack page
     *
     * check for the following two things on the user virtual address:
     * 1) the address is above PHYS_BASE - STACK_MAX
     * 2) PUSH/PUSHA instruction can allocate a maximum of 32 bytes on the stack -
     *      ensure the address is at least 32 bytes below the current stack pointer
     */
    // printf ("page_for_addr(): address = %p\n\n", address);
    if ((p.vaddr > (PHYS_BASE - STACK_MAX)) && ((address + 32) >= (void *) t->user_esp)) {
        /* allocate a stack page */
        // printf ("allocating a page in page_for_addr()\n");
        return page_allocate ((void *) p.vaddr, false);
    }

    /* invalid virtual address - reject it and return NULL */
    // printf("address = %p\n\n", address);
    return NULL;
}

/* Locks a frame for page P and pages it in.
   Returns true if successful, false on failure. */
static bool
do_page_in (struct page *p)
{
    /* first step: get a frame for the page */
    p->frame = frame_alloc_and_lock (p);
    if (p->frame == NULL)
        return false;

    /* use this Ed post */
    /* https://edstem.org/us/courses/37749/discussion/3060220 */

    /* handle logic for reading in from a file */
    if (p->file != NULL) {
        // printf ("NOT A NULL FILE\n\n\n\n\n\n");
        lock_acquire (&filesys_lock);
        off_t read_bytes = file_read_at (p->file, p->frame->base, p->file_bytes, p->file_offset);
        lock_release (&filesys_lock);
        off_t non_read_bytes = PGSIZE - read_bytes;

        /* zero out the rest of the frame */
        // printf ("do_page_in(): filling %d bytes with 0s\n", non_read_bytes);
        memset (p->frame->base + read_bytes, 0, non_read_bytes);

        /* check if read_bytes is not equal to file_bytes */
        if (read_bytes != p->file_bytes) {
            // printf ("do_page_in(): read_bytes (%d) != p->file_bytes (%d)\n\n",
            //     read_bytes, p->file_bytes);
            return false;
        }

        return true;
    }

    /* TODO: handle logic for swapping in from swap disk */
    if (p->sector != (block_sector_t) -1) {
        /* read in from swap disk */
        swap_in (p);
        return true;
    }

    /* final step: just return a zero-ed out physical frame */
    // printf ("do_page_in(): zero-ed out physical frame at base %p\n", p->frame->base);
    memset (p->frame->base, 0, PGSIZE);
    return true;
}

/* Faults in the page containing FAULT_ADDR.
   Returns true if successful, false on failure. */
bool
page_in (void *fault_addr)
{
    bool install;
    struct thread *t = thread_current ();

    /* ensure that the supplementary page table exists */
    if (t->pages == NULL) {
        return false;
    }

    struct page *p = page_for_addr (fault_addr);

    // printf ("page_in()\n\n\n\n\n\n");

    /* check if the page exists */
    if (p == NULL) {
        // printf ("page_in(): p == NULL\n\n\n\n\n\n");
        return false;
    }

    /* must acquire the lock of the frame in current process */
    frame_lock (p);

    /* check if the page has a frame */
    if (p->frame == NULL && !do_page_in (p)) {
        // printf ("PAGE DOESN'T HAVE A FRAME\n\n\n\n\n\n");
        /* attempt page in of page that caused page fault */
        // if (!do_page_in (p)) {
            /* page in failed */
        frame_unlock (p->frame);
        return false;
        // }
    }

    /* install page into page directory, flip read_only bit for write access */
    install = pagedir_set_page (t->pagedir, p->vaddr, p->frame->base, !p->read_only);

    /* release the lock of the frame in current process */
    frame_unlock (p->frame);

    return install;
}

/* TODO: Evicts page P.
   P must have a locked frame.
   Return true if successful, false on failure. */
bool
page_out (struct page *p)
{
    // printf("hitting page out\n");
    struct frame *f;
    // get the page's frame
    f = p->frame;
    // check it has a locked frame
    if (f == NULL)
        return false;
    // check if the frame is locked
    ASSERT (lock_held_by_current_thread (&f->lock));

    pagedir_clear_page(p->thread->pagedir, p->vaddr);

    bool try_swap = false;

    // if (!pagedir_is_dirty(p->thread->pagedir, p->vaddr)) {
    //     try_swap = true;
    // }

    if (p->file == NULL) {
        try_swap = swap_out(p);
    }
    if (try_swap) {
        p->frame = NULL;
    }
    return try_swap;





    // check if the page is dirty using the frame's pagedir
    // if (pagedir_is_dirty(p->thread->pagedir, p->vaddr))
    // {
    //     block_sector_t out_sector;
    //     if (swap_out(p))
    //     {
    //         p->sector = out_sector;
    //         // pagedir_clear_page(f->page->thread->pagedir, p->vaddr);
    //     }
    //     else
    //     {
    //         return false;
    //     }
    // }
    // remove the page from the frame's process's page table
    // hash_delete(&f->page->thread->pages, &p->elem);
    // free the frame
    // frame_free(f);
    // return true;
}

/* Returns true if page P's data has been accessed recently,
   false otherwise.
   P must have a frame locked into memory. */
bool
page_accessed_recently (struct page *p)
{
    /* used for clock algorithm
     * we don't need this function
     */
    /* assert p has a frame locked into memory */
    // ASSERT (lock_held_by_current_thread (&p->frame->lock));
    // ASSERT (p->frame != NULL);

    // if (pagedir_is_accessed (p->thread->pagedir, p->vaddr)) {
    //     /* if the page has been accessed recently, reset bit */
    //     pagedir_set_accessed (p->thread->pagedir, p->vaddr, false);
    //     return true;
    // }

    // return false;

}

/* Adds a mapping for user virtual address VADDR to the page hash
   table. Fails if VADDR is already mapped or if memory
   allocation fails. */
struct page *
page_allocate (void *vaddr, bool read_only)
{
    /* round down the virtual address to the nearest page boundary */
    void *rounded_down_vaddr = pg_round_down (vaddr);

    /* allocate memory for the page */
    struct thread *t = thread_current ();
    struct page *p = malloc (sizeof *p);
    struct hash_elem *h;

    if (p == NULL)
        return NULL; /* out of memory */

    /* initialize the page */
    p->vaddr = rounded_down_vaddr;
    p->read_only = read_only;
    p->frame = NULL;
    p->file = NULL;
    p->file_offset = 0;
    p->file_bytes = 0;
    p->sector = (block_sector_t) -1;
    p->thread = t;

    h = hash_insert (t->pages, &p->elem);
    // printf("page base is %p\n", p->vaddr);
    if (h == NULL)
        return p; /* success, page has been inserted into the page table */

    /* page already exists in the page table */
    free (p);
    return NULL;
}

/* TODO: Evicts the page containing address VADDR
   and removes it from the page table. */
void
page_deallocate (void *vaddr)
{
    /* NEVER USED */
    // round down the virtual address to the nearest page boundary
    void *page = pg_round_down (vaddr);
    // get the page containing the virtual address
    struct page *p = page_for_addr (page);
    // check if the page is in the current process's page table
    if (p == NULL)
        return;

    // remove the page from the current process's page table
    hash_delete (&thread_current ()->pages, &p->elem);
    // free the page
    free (p);
}

/* Returns a hash value for the page that E refers to. */
unsigned
page_hash (const struct hash_elem *e, void *aux UNUSED)
{
    /* extract page that hash element refers */
    struct page *p = hash_entry (e, struct page, elem);

    unsigned hash = hash_bytes (&p->vaddr, sizeof p->vaddr);
    // unsigned hash_output = (hash >> 16) ^ hash;

    // printf("hash is %u\n", hash_output);

    /* extrac hash value -- asked Roy for inspiration in office hours */
    unsigned output = (unsigned) p->vaddr >> PGBITS;
    return output;
}

/* Returns true if page A precedes page B. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
    /* extract pages that hash elements refer */
    struct page *a = hash_entry (a_, struct page, elem);
    struct page *b = hash_entry (b_, struct page, elem);

    /* compare virtual addresses' values */
    return a->vaddr < b->vaddr;
}

/* TODO: Tries to lock the page containing ADDR into physical memory.
   If WILL_WRITE is true, the page must be writeable;
   otherwise it may be read-only.
   Returns true if successful, false on failure. */
bool
page_lock (const void *addr, bool will_write)
{
    // round down the virtual address to the nearest page boundary
    // void *page = pg_round_down (addr);
    // get the page containing the virtual address
    struct page *p = page_for_addr (addr);
    // if not found or is read only, return false
    if (p == NULL || (will_write && p->read_only))
        return false;

    /* lock the frame here to prevent kernel page faults and
     * synchronization problems
    */
    frame_lock (p);

    // check if the page is already locked
    if (p->frame == NULL) {
        bool paged_in = do_page_in (p);
        bool set_page = pagedir_set_page (thread_current ()->pagedir, p->vaddr, p->frame->base, !p->read_only);

        /* both conditions must have been met -- otherwise operation failed */
        if (!paged_in || !set_page) {
            // frame_unlock (p->frame);
            return false;
        }

    }

    return true;
}

/* TODO: Unlocks a page locked with page_lock(). */
void
page_unlock (const void *addr)
{
    // round down the virtual address to the nearest page boundary
    // void *page = pg_round_down (addr);
    // get the page containing the virtual address
    struct page *p = page_for_addr (addr);
    // assert p is not equal to NULL
    ASSERT (p != NULL);

    /* avoid return statement, just assertion is enough */
    // if (p == NULL)
    //     return false;
    // unlock the frame
    frame_unlock (p->frame);
    // return true;
}

/*
---*--- Don't use this function! Use pagedir_set_page () instead. ---*---
*/

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current ();

    /* Verify that there's not already a page at that virtual
        address, then map our page there. */
    return (pagedir_get_page (t->pagedir, upage) == NULL
            && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
int
get_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
