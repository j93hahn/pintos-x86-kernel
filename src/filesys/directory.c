#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/inode.h"
#include "filesys/free-map.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory in the given SECTOR.
   The directory's parent is in PARENT_SECTOR.
   Returns inode of created directory if successful,
   null pointer on failure.
   On failure, SECTOR is released in the free map - accomplished via
   successive calls to inode_remove() and inode_close() in all cases
   of failure. */
struct inode *
dir_create (block_sector_t sector, block_sector_t parent_sector)
{
    /* create a directory inode in the given sector */
    struct inode *inode = inode_create (sector, DIR_INODE);
    if (inode == NULL) {
        inode_remove (inode);
        inode_close (inode);
        return NULL;
    }

    /* buffer to store connections between '.'/'..' and sectors */
    struct dir_entry e[2];

    /* step 1a: create '.' - current working directory */
    e[0].inode_sector = sector;
    e[0].name[0] = '.';
    e[0].name[1] = '\0';
    e[0].in_use = true;

    /* step 1b: create '..' - parent working directory */
    e[1].inode_sector = parent_sector;
    e[1].name[0] = '.';
    e[1].name[1] = '.';
    e[1].name[2] = '\0';
    e[1].in_use = true;

    /* step 2: write the '.'/'..' dir_entries to disk */
    if (inode_write_at (inode, &e, sizeof e, 0) != sizeof e) {
        inode_remove (inode);
        inode_close (inode);
        return NULL;
    }

    /* return created directory inode */
    return inode;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL && inode_get_type (inode) == DIR_INODE)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;
  bool ok;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  inode_lock (dir->inode);
  ok = lookup (dir, name, &e, NULL);
  inode_unlock (dir->inode);

  *inode = ok ? inode_open (e.inode_sector) : NULL;
  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strchr (name, '/') || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  inode_lock (dir->inode);
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  inode_unlock (dir->inode);
  return success;
}


/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct dir *dir_to_remove = NULL;

  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (!strcmp (name, ".") || !strcmp (name, "..")) {
    // printf ("strcmp () failed\n");
    return false;
  }

  /* Find directory entry. */
  inode_lock (dir->inode);
  if (!lookup (dir, name, &e, &ofs)) {
    // printf ("lookup failed\n");
    goto done;
  }

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL) {
    // printf ("inode is NULL\n");
    goto done;
  }

  /* Verify that inode is not in-use; check it's a directory inode and
   * open_cnt > 1 since we jsut called inode_open () on the sector */
  if (inode_get_type (inode) == DIR_INODE && inode_open_cnt (inode) > 1) {
    // printf ("inode is in-use\n");
    goto done;
  }



// OLD LOGIC: DOES NOT WORK
  // inode_unlock (dir->inode); /* unlock inode as dir_readdir() calls lock()*/

  // /* Verify that inode is not an empty directory via dir_readdir () */
  // if (inode_get_type (inode) == DIR_INODE && dir_readdir (dir, name)) {
  //   // printf ("inode is not-empty\n");
  //   inode_lock (dir->inode);    /* re-lock inode */
  //   goto done;
  // }

  // inode_lock (dir->inode);  /* re-lock inode */

  // NEW LOGIC: WORKS
  if (inode_get_type (inode) == DIR_INODE) {
    inode_lock(inode);
    int open_cnt = inode_open_cnt (inode);
    if (open_cnt > 1) {
      inode_unlock (inode);
      goto done;
    }
    inode_unlock (inode);
    dir_to_remove = dir_open (inode);
    char *cook = malloc (strlen (name) + 1);
    if (dir_readdir (dir_to_remove, cook)) {
      goto done;
    }
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) {
    // printf ("inode_write_at failed\n");
    goto done;
  }

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  if (dir_to_remove != NULL) {
    dir_close (dir_to_remove);
  }
  inode_unlock (dir->inode);
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  inode_lock (dir->inode);
  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;

      if (e.in_use && strcmp (e.name, ".") && strcmp (e.name, ".."))
        /* check that the directory entry is in use and that the name is
         * neither '.' nor '..' because we don't care about those special
         * directory entries; the information is not "well-defined" */
        {
          inode_unlock (dir->inode);
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  inode_unlock (dir->inode);
  return false;
}
