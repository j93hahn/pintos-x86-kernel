#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "filesys/off_t.h"
#include "filesys/file.h"
#include <stdbool.h>
#include "devices/block.h"


#define STACK_MAX (1024 * 1024)


/* Virtual page struct. */
struct page {
    void *vaddr;                    /* User virtual address. */
    struct frame *frame;            /* Mapped page frame. */
    struct thread *thread;          /* Owning thread. */
    bool read_only;                 /* Read-only page? */
    bool private;                   /* Private page? */
    struct hash_elem elem;          /* Hash element. */
    struct file *file;              /* File. */
    off_t file_offset;              /* Offset in file. */
    off_t file_bytes;               /* Bytes to read/write, from 1 to PGSIZE */
    block_sector_t sector;          /* Starting sector in swap area. */
};

int get_user (const uint8_t *uaddr);
bool put_user (uint8_t *udst, uint8_t byte);
void page_exit (void);
struct page *page_for_addr (const void *address);
bool page_in (void *fault_addr);
bool page_out (struct page *p);
bool page_accessed_recently (struct page *p);
struct page* page_allocate (void *vaddr, bool read_only);
void page_deallocate (void *vaddr);
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
bool page_lock (const void *addr, bool will_write);
void page_unlock (const void *addr);
bool install_page (void *upage, void *kpage, bool writable);

#endif
