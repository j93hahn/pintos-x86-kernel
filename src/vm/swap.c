#include "vm/swap.h"

/* The swap device. */
static struct block *swap_device;

/* Used swap pages. */
static struct bitmap *swap_bitmap;

/* Protects swap_bitmap. */
static struct lock swap_lock;

/* Number of sectors per page. */
#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

/* Set up swapping mechanism - given code. */
void
swap_init (void)
{
    swap_device = block_get_role (BLOCK_SWAP);
    if (swap_device == NULL) {
        printf ("no swap device--swap disabled\n");
        swap_bitmap = bitmap_create (0);
    } else
        swap_bitmap = bitmap_create (block_size (swap_device)
                                    / PAGE_SECTORS);
    if (swap_bitmap == NULL)
        PANIC ("couldn't create swap bitmap");
    lock_init (&swap_lock);
}

/* Swaps in page P, which must have a locked frame
   (and be swapped out). */
void
swap_in (struct page *p)
{
    // printf ("swap in\n");
    ASSERT (lock_held_by_current_thread (&p->frame->lock));
    ASSERT (p->frame != NULL);

    /* sector must not be -1; page should be in filesystem */
    ASSERT (p->sector != (block_sector_t) -1);

    /* read in filesystem data, block by block into DRAM */
    for (size_t i = 0; i < PAGE_SECTORS; i++) {
        /* read in the information at page sector and stores it block by block
            into p->frame->base */
        block_read (swap_device, p->sector + i, p->frame->base + i * BLOCK_SECTOR_SIZE);
    }

    /* TODO: reset the bitmap */
    bitmap_reset (swap_bitmap, p->sector / PAGE_SECTORS);

    /* set sector to -1; page is now in DRAM, not filesystem */
    p->sector = (block_sector_t) -1;
}

/* Swaps out page P, which must have a locked frame. */
bool
swap_out (struct page *p)
{
    // printf ("swap out\n");
    ASSERT (lock_held_by_current_thread (&p->frame->lock));
    ASSERT (p->frame != NULL);

    /* first step: identify a swap slot in the bitmap */
    lock_acquire (&swap_lock);
    size_t swap_slot = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    lock_release (&swap_lock);

    /* Return false if no swap slot is available */
    if (swap_slot == BITMAP_ERROR) {
        return false;
    }

    /* calculate sector location, which is just location in the swap bitmap
        multiplied by the number of sectors per page to store full information */
    p->sector = swap_slot * PAGE_SECTORS;

    /* write out page sectors, block by block into filesystem */
    for (size_t i = 0; i < PAGE_SECTORS; i++) {
        /* write out the information at p->frame->base block by block into
            filesystem at calculated page sector */
        block_write (swap_device, p->sector + i, p->frame->base + i * BLOCK_SECTOR_SIZE);
    }

    p->file = NULL;         /* won't read in from some code segment or something */

    /* Return true to indicate success */
    return true;
}

/* Frees swap slot SLOT, which must be in use. */
void
swap_free (size_t slot)
{
    lock_acquire (&swap_lock);
    bitmap_reset (swap_bitmap, slot);
    lock_release (&swap_lock);
}
