#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "vm/page.h"


/* Frame structure */
struct frame {
    void *base;                     /* Kernel virtual address */
    struct page *page;              /* Mapped process page */
    struct lock lock;               /* Lock */

    /* TODO: are these required elements? */
    struct list_elem elem;          /* List element */
    struct thread *thread;          /* Thread */
};

void frame_init (void);
void frame_lock (struct page *p);
void frame_free (struct frame *f);
void frame_unlock (struct frame *f);
struct frame* frame_alloc_and_lock (struct page *page);

#endif
