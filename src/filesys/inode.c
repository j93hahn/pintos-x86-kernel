#include "filesys/inode.h"
#include <bitmap.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_CNT 123
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT                                              \
                     + PTRS_PER_SECTOR * INDIRECT_CNT                        \
                     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
                    * BLOCK_SECTOR_SIZE)

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors[SECTOR_CNT]; /* Sectors. */
    enum inode_type type;               /* FILE_INODE or DIR_INODE. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
    return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    struct lock lock;                   /* Protects the inode. */

    /* Denying writes. */
    struct lock deny_write_lock;        /* Protects members below. */
    struct condition no_writers_cond;   /* Signaled when no writers. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    int writer_cnt;                     /* Number of writers. */
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Controls access to open_inodes list. */
static struct lock open_inodes_lock;

static void deallocate_inode (const struct inode *);

/* Initializes the inode module. */
void
inode_init (void)
{
    list_init (&open_inodes);
    lock_init (&open_inodes_lock);
}

/* Extracts inode data from disk given inode's sector location. */
static inline struct inode_disk *
read_inode (block_sector_t sector)
{
    struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode == NULL)
        PANIC ("inode.c - read_inode(): disk_inode allocation failed\n");
    block_read (fs_device, sector, disk_inode);
    return disk_inode;

    /*
     *              **** important ****
     * don't forget to free disk_inode after it's been used
     */
}

/* Initializes an inode of the given TYPE, writes the new inode
   to sector SECTOR on the file system device, and returns the
   inode thus created.  Returns a null pointer if unsuccessful,
   in which case SECTOR is released in the free map. */
struct inode *
inode_create (block_sector_t sector, enum inode_type type)
{
    /* block_write() on new inode_disk here, then call inode_open() */
    struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode == NULL)
        PANIC ("inode.c - inode_create(): disk_inode allocation failed\n");

    /* If this assertion fails, the inode structure is not exactly
       one sector in size and MUST be fixed. */
    ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    disk_inode->type = type;
    disk_inode->length = 0;
    disk_inode->magic = INODE_MAGIC;

    /* Write inode_disk to sector. */
    block_write (fs_device, sector, disk_inode);
    free (disk_inode);

    struct inode *inode = inode_open (sector);
    if (inode == NULL) {
        return NULL;
    }

    return inode;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
        e = list_next (e))
        {
        inode = list_entry (e, struct inode, elem);
        if (inode->sector == sector)
            {
            // printf("inode already open, reopening\n");
            return inode_reopen (inode);
            }
        }

    /* Allocate memory on the heap for the inode struct. */
    inode = malloc (sizeof *inode);
    if (inode == NULL)
        return NULL;

    /* Initialize. */
    list_push_front (&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->removed = false;

    /* Initialize open_cnt to 1 to guarantee that inode will not be
       evicted from inode cache. */
    lock_acquire (&open_inodes_lock);
    // printf("initializing inode open count to 1\n");
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    lock_release (&open_inodes_lock);

    /* Initialize synchronization tools. */
    lock_init (&inode->lock);
    lock_init (&inode->deny_write_lock);
    cond_init (&inode->no_writers_cond);

    return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
    if (inode != NULL) {
        lock_acquire (&open_inodes_lock);
        inode->open_cnt++;
        // printf("increasing inode open count from %d to %d\n", inode->open_cnt, inode->open_cnt + 1);
        lock_release (&open_inodes_lock);
    }
    return inode;
}

/* Returns the type of INODE. */
enum inode_type
inode_get_type (const struct inode *inode)
{
    ASSERT (inode != NULL);
    struct inode_disk *disk_inode = read_inode (inode->sector);
    enum inode_type type = disk_inode->type;
    free (disk_inode);
    return type;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
    return inode->sector;
}

/* If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

    lock_acquire (&open_inodes_lock);
    // printf("decreasing inode open count from %d to %d\n", inode->open_cnt, inode->open_cnt - 1);
    int open_cnt = --inode->open_cnt;
    lock_release (&open_inodes_lock);

    /* Release resources if this was the last opener. */
    if (open_cnt == 0) {
        /* Remove from inode list and release lock. */
        // print which inode is being removed from the list
        // printf("removing inode from the list\n");
        list_remove (&inode->elem);

        if (inode->removed) {   /* Deallocate blocks if removed. */
            deallocate_inode (inode);
        } else {
            /* Write inode to disk again for peace of mind. */
            struct inode_disk *disk_inode = read_inode (inode->sector);
            block_write (fs_device, inode->sector, disk_inode);
            free (disk_inode);
        }

        free (inode);
    }
}

/* Deallocates SECTOR and anything it points to recursively.
   LEVEL is 2 if SECTOR is doubly indirect,
   or 1 if SECTOR is indirect,
   or 0 if SECTOR is a data sector. */
static void
deallocate_recursive (block_sector_t sector, int level)
{
    if (level == 0)                     /* direct blocks */
    {
        if (sector != 0) {  /* check if !NULL sector */
            /* check if !NULL sector, release bitmap */
            free_map_release (sector);
        }
    }
    else if (level == 1 || level == 2)  /* indirection */
    {
        if (sector != 0) {  /* must also check that the sector is !NULL */
            /* first, read data to extract PTRS_PER_SECTOR number of sectors */
            block_sector_t *indirect_block = calloc (1, sizeof *indirect_block);
            if (indirect_block == NULL)
            {
                PANIC ("inode.c - deallocate_recursive(): calloc failed on \
                    indirect blocks\n");
            }
            block_read (fs_device, sector, indirect_block);

            /* for each extracted sector, check if valid then deallocate */
            for (int i = 0; i < PTRS_PER_SECTOR; i++)
            {
                if (indirect_block[i] != 0)
                {
                    deallocate_recursive (indirect_block[i], level - 1);
                }
            }
            free (indirect_block);  /* free calloc'ed memory */
        }
    }
    else
    {
        NOT_REACHED ();
    }
}

/* Deallocates the blocks allocated for INODE. */
static void
deallocate_inode (const struct inode *inode)
{
    /* extract inode_disk struct */
    struct inode_disk *disk_inode = read_inode (inode->sector);

    /* deallocate direct blocks */
    for (int i = 0; i < DIRECT_CNT; i++) {
        deallocate_recursive (disk_inode->sectors[i], 0);
    }

    /* deallocate indirect block pointers */
    deallocate_recursive (disk_inode->sectors[DIRECT_CNT], 1);

    /* deallocate doubly indirect block pointers */
    deallocate_recursive (disk_inode->sectors[DIRECT_CNT + INDIRECT_CNT], 2);

    /* deallocate sector used for the inode block stored in memory
     * this step must be completed after deallocating the free_map sectors
     * stored in the disk_inode however, to ensure that the disk_inode still
     * has access to the proper location as a benchmark */
    deallocate_recursive (inode->sector, 0);

    /* free disk_inode struct*/
    free (disk_inode);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
    ASSERT (inode != NULL);
    inode->removed = true;
}

/* Translates SECTOR_IDX into a sequence of block indexes in
   OFFSETS and sets *OFFSET_CNT to the number of offsets.
   offset_cnt can be 1 to 3 depending on whether sector_idx
   points to sectors within DIRECT, INDIRECT, or DBL_INDIRECT ranges.
*/
static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
    ASSERT (sector_idx >= 0);

    /* Handle direct blocks. When sector_idx < DIRECT_CNT */
    if (sector_idx < DIRECT_CNT)
    {
        /* disk_inode->sectors[sector_idx] stores direct block */
        offsets[0] = sector_idx;

        /* number of offsets to calculate */
        *offset_cnt = 1;
        return;
    }

    /* Handle indirect blocks. */
    else if (sector_idx < DIRECT_CNT + INDIRECT_CNT * PTRS_PER_SECTOR)
    {
        /* disk_inode->sectors[123] stores indirect block */
        offsets[0] = DIRECT_CNT;

        /* stores offset within the indirect block */
        offsets[1] = (sector_idx - DIRECT_CNT) % PTRS_PER_SECTOR;

        /* number of offsets to calculate */
        *offset_cnt = 2;
        return;
    }

    /* Handle doubly indirect blocks. */
    else if (sector_idx < INODE_SPAN / BLOCK_SECTOR_SIZE)
    {
        /* disk_inode->sectors[124] stores doubly indirect block */
        offsets[0] = DIRECT_CNT + INDIRECT_CNT;

        /* stores offset within the doubly indirect block */
        offsets[1] = (sector_idx - (DIRECT_CNT + INDIRECT_CNT * PTRS_PER_SECTOR)) / PTRS_PER_SECTOR;

        /* stores offset within the indirect block pointed to by the
         * doubly indirect block*/
        offsets[2] = (sector_idx - (DIRECT_CNT + INDIRECT_CNT * PTRS_PER_SECTOR)) % PTRS_PER_SECTOR;

        /* number of offsets to calculate */
        *offset_cnt = 3;
        return;
    }

    /* sector_idx is out of range */
    else
    {
        NOT_REACHED ();
    }
}

/* Retrieves the data block for the given byte OFFSET in INODE,
   setting *DATA_BLOCK to the block and data_sector to the sector to write
   (for inode_write_at method).
   Returns true if successful, false on failure.
   If ALLOCATE is false (usually for inode read), then missing blocks
   will be successful with *DATA_BLOCK set to a null pointer.
   If ALLOCATE is true (for inode write), then missing blocks will be allocated.
   This method may be called in parallel */
static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,
                void **data_block, block_sector_t *data_sector)
{
  /* calculate_indices ... then access the sectors in the sequence
   * indicated by calculate_indices
   * Don't forget to check whether the block is allocated (e.g., direct, indirect,
   * and double indirect sectors may be zero/unallocated, which needs to be handled
   * based on the bool allocate */
    size_t offsets[3];
    size_t offset_cnt, loop_idx = 0;
    calculate_indices (offset / BLOCK_SECTOR_SIZE, offsets, &offset_cnt);

    *data_block = calloc (1, BLOCK_SECTOR_SIZE); /* free in inode_*_at */
    if (*data_block == NULL)
    {
        PANIC ("inode.c - get_data_block(): calloc failed for *data_block\n");
    }

    block_sector_t sector = inode->sector;
    while (loop_idx < offset_cnt) {     /* loop through offsets */
        struct inode_disk *disk_inode = read_inode (sector); /* extract inode disk information */

        if (disk_inode->sectors[offsets[loop_idx]] == 0) /* check if unallocated */
        {
            if (!allocate)  /* if allocate bit is turned off, data block cannot be retrieved */
            {
                free (*data_block);
                *data_block = NULL;
                free (disk_inode);
                return true;
            }
            else    /* allocate new data block in free_map */
            {
                if (!free_map_allocate (&disk_inode->sectors[offsets[loop_idx]]))
                {
                    free (*data_block);
                    free (disk_inode);
                    return false;
                }
                else    /* successfully allocated new data block - must write data to disk
                         * via successive block write operations */
                {
                    block_write (fs_device, sector, disk_inode);
                    if (loop_idx + 1 == offset_cnt) /* allocate data block */
                    {
                        block_write (fs_device, disk_inode->sectors[offsets[loop_idx]], *data_block);
                        *data_sector = disk_inode->sectors[offsets[loop_idx]];
                        block_read (fs_device, *data_sector, *data_block);
                        free (disk_inode);
                        return true;
                    }
                    else    /* allocate pointer block */
                    {
                        block_sector_t *indirect_block = calloc (1, BLOCK_SECTOR_SIZE);
                        if (indirect_block == NULL)
                        {
                            PANIC ("inode.c - get_data_block(): calloc failed for *indirect_block\n");
                        }

                        /* write indirect_block information to disk then free heap-allocation */
                        block_write (fs_device, disk_inode->sectors[offsets[loop_idx]], indirect_block);
                        free (indirect_block);
                    }
                }
            }
        }
        /* sector has already been allocated on disk; check data block's existence */
        sector = disk_inode->sectors[offsets[loop_idx]]; /* update sector to trace from the
                                                          * new sector for indirection */

        if (loop_idx + 1 == offset_cnt)
        {
            *data_sector = sector;
            block_read (fs_device, *data_sector, *data_block);
            free (disk_inode);
            return true;
        }
        else    /* don't do anything - already allocated current
                * level of indirection; it's stored in inode disk
                *      -> just update sector variable
                */
        {
            /* do nothing! */
        }

        /* loop to next offset */
        loop_idx++;

        /* free disk_inode memory for current iteration */
        free (disk_inode);
    }

    free (*data_block);
    NOT_REACHED (); /* should never hit here */
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached.
   Some modifications might be needed for this function template. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    block_sector_t target_sector = 0; // not really useful for inode_read

    while (size > 0)
        {
        /* Sector to read, starting byte offset within sector, sector data. */
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;
        void *block;    // may need to be allocated in get_data_block method,
                        // and don't forget to free it in the end

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length (inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0 || !get_data_block (inode, offset, false, &block, &target_sector))
            break;

        if (block == NULL)
            memset (buffer + bytes_read, 0, chunk_size);
        else
            {
            memcpy (buffer + bytes_read, block + sector_ofs, chunk_size);
            }

        /* free the block */
        free (block);

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
        }

    return bytes_read;
}

/* Extends INODE to be at least LENGTH bytes long. */
static void
extend_file (struct inode *inode, off_t length)
{
    /* Write new sectors and add to inode. */
    struct inode_disk *disk_inode = read_inode (inode->sector);
    if (length >= disk_inode->length) { /* only update length if new length is
                                         * longer than current length */
        disk_inode->length = length;
    }
    block_write (fs_device, inode->sector, disk_inode);
    free (disk_inode);
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs.
   Some modifications might be needed for this function template.*/
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    block_sector_t target_sector = 0;

    /* Don't write if writes are denied. */
    lock_acquire (&inode->deny_write_lock);
    if (inode->deny_write_cnt)
        {
        lock_release (&inode->deny_write_lock);
        return 0;
        }
    inode->writer_cnt++;
    lock_release (&inode->deny_write_lock);

    while (size > 0)
        {
        /* Sector to write, starting byte offset within sector, sector data. */
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;
        void *block;    // may need to be allocated in get_data_block method,
                        // and don't forget to free it in the end

        /* Bytes to max inode size, bytes left in sector, lesser of the two. */
        off_t inode_left = INODE_SPAN - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;

        if (chunk_size <= 0 || !get_data_block (inode, offset, true, &block, &target_sector)) {
            break;
        }

        memcpy (block + sector_ofs, buffer + bytes_written, chunk_size);
        block_write (fs_device, target_sector, block);

        /* free the block */
        free (block);

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
        }

    extend_file (inode, offset);

    lock_acquire (&inode->deny_write_lock);
    if (--inode->writer_cnt == 0)
        cond_signal (&inode->no_writers_cond, &inode->deny_write_lock);
    lock_release (&inode->deny_write_lock);

    return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
    ASSERT (inode->deny_write_cnt >= 0);
    ASSERT (inode->deny_write_cnt < inode->open_cnt);

    lock_acquire (&inode->deny_write_lock);
    while (inode->writer_cnt > 0)
        cond_wait (&inode->no_writers_cond, &inode->deny_write_lock);
    inode->deny_write_cnt++;
    lock_release (&inode->deny_write_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
    ASSERT (inode->deny_write_cnt > 0);
    ASSERT (inode->deny_write_cnt <= inode->open_cnt);

    lock_acquire (&inode->deny_write_lock);
    inode->deny_write_cnt--;

    /* TA NOTE: following lines are not necessary */
    // if (inode->deny_write_cnt == 0)
    //     cond_broadcast (&inode->no_writers_cond, &inode->deny_write_lock);
    lock_release (&inode->deny_write_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
    struct inode_disk *disk_inode = read_inode (inode->sector);
    off_t length = disk_inode->length;
    free (disk_inode);
    return length;
}

/* Returns the number of openers. */
int
inode_open_cnt (const struct inode *inode)
{
    int open_cnt;

    lock_acquire (&open_inodes_lock);
    open_cnt = inode->open_cnt;
    lock_release (&open_inodes_lock);

    return open_cnt;
}

/* Locks INODE. */
void
inode_lock (struct inode *inode)
{
    ASSERT (inode != NULL);
    lock_acquire (&inode->lock);
}

/* Releases INODE's lock. */
void
inode_unlock (struct inode *inode)
{
    ASSERT (inode != NULL);
    lock_release (&inode->lock);
}
