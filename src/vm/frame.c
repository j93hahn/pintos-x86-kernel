#include "vm/frame.h"
#include "vm/swap.h"
#include "devices/timer.h"
#include "lib/string.h"

/*
Managing the frame table

The main job is to obtain a free frame to map a page to. To do so:

1. Easy situation is there is a free frame in frame table and it can be
obtained. If there is no free frame, you need to choose a frame to evict
using your page replacement algorithm based on setting accessed and dirty
bits for each page. See section 4.1.5.1 and A.7.3 to know details of
replacement algorithm(accessed and dirty bits) If no frame can be evicted
without allocating a swap slot and swap is full, you should panic the
kernel.

2. Remove references from any page table that refers to.

3. Write the page to file system or swap.
*/

/* global variables used in frame_init */
static struct frame *frame_table;
static size_t frame_cnt;

static struct lock scan_lock;
static size_t hand;
static size_t rnd_robin_cntr;

/* Initializes the frame table. */
void
frame_init (void)
{
    void *base;

    /* this lock is required to access anything
        in the physical memory frame table */
    lock_init (&scan_lock);

    frame_table = malloc (sizeof *frame_table * init_ram_pages);
    if (frame_table == NULL) {
        PANIC ("out of memory allocating page frames");
    }

    while ((base = palloc_get_page (PAL_USER)) != NULL) {
        struct frame *f = &frame_table[frame_cnt++];
        lock_init (&f->lock);
        f->base = base;
        f->page = NULL;
    }
    // printf("frame count %d\n:", frame_cnt);
}

/* Tries to allocate and lock a frame for PAGE.
   Returns the frame if successful, NULL on failure. */
static struct frame *
try_frame_alloc_and_lock (struct page *page)
{
    struct frame *f = NULL;

    /* acquire scan lock for determining if frame exists */
    lock_acquire (&scan_lock);

    /* iterate through all free frames first */
    for (int i = 0; i < frame_cnt; i++) {
        struct frame *f = &frame_table[i];
        if (lock_try_acquire (&f->lock)) {
            if (f->page == NULL) {
                f->page = page;
                lock_release (&scan_lock);
                return f;
            }
            lock_release (&f->lock);
        }
    }

    // couldn't find a free frame so evict the first non-null frame, round robin style
    int rnd_rob_cntr = 0;
    for (int i = 0; i < frame_cnt * 2; i++) {
        struct frame *f = &frame_table[rnd_robin_cntr % frame_cnt];
        rnd_robin_cntr += 1;
        if (lock_try_acquire (&f->lock)) {
            if (f->page==NULL) {
                f->page=page;
                lock_release (&scan_lock);
                return f;
            }
            lock_release(&scan_lock);
            if (!page_out(f->page)) {
                lock_release (&f->lock);
                return NULL;
            }
            f->page=page;
            return f;
        }
    }
    lock_release (&scan_lock);
    return NULL;
}

/* Tries really hard to allocate and lock a frame for PAGE.
   Returns the frame if successful, NULL on failure. */
struct frame *
frame_alloc_and_lock (struct page *page)
{
    for (int i = 0; i < 10; i++) {
        struct frame *f = try_frame_alloc_and_lock (page);
        if (f != NULL) {
            return f;
        }
        timer_msleep (100);
    }

    /* frame allocation failed */
    return NULL;
}

/* Locks P's frame into memory, if it has one.
   Upon return, p->frame will not change until P is unlocked. */
void
frame_lock (struct page *p)
{
    /* extract physical frame of the page */
    // struct frame *f = p->frame;
    // if (f != NULL) {
    //     lock_acquire (&f->lock);

    //     /* release the old frame if it has changed and try again */
    //     if (p->frame != f) {
    //         lock_release (&f->lock);
    //     }
    // }
    struct frame *f;

    do {
        /* extract physical frame of the page */
        f = p->frame;
        if (f != NULL) {
            lock_acquire (&f->lock);

            /* release the old frame if it has changed and try again */
            if (p->frame != f) {
                lock_release (&f->lock);
            }
        }
    } while (p->frame != f);
}

/* Releases frame F for use by another page.
   F must be locked for use by the current process.
   Any data in F is lost. */
void
frame_free (struct frame *f)
{
    /* assert F is locked by the current process */
    ASSERT (lock_held_by_current_thread (&f->lock));

    /* clear the frame */
    f->page = NULL;
    // clear it using memset
    // memset(f->base, 0, PGSIZE);
    lock_release (&f->lock);
}

/* Unlocks frame F, allowing it to be evicted.
   F must be locked for use by the current process. */
void
frame_unlock (struct frame *f)
{
    /* assert F is locked by the current process */
    ASSERT (lock_held_by_current_thread (&f->lock));

    /* release the frame */
    lock_release (&f->lock);
}
