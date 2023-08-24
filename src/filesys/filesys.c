#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "lib/string.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  free_map_close ();
}

/* Extracts a file name part from *SRCP into PART,
   and updates *SRCP so that the next call will return the next
   file name part.
   Returns 1 if successful, 0 at end of string, -1 for a too-long
   file name part. */
static int
get_next_part (char part[NAME_MAX], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes.
     If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.
     Add null terminator. */
  while (*src != '/' && *src != '\0')
    {
      if (dst < part + NAME_MAX)
        *dst++ = *src;
      else
        return -1;
      src++;
    }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Resolves relative or absolute file NAME.
   Returns true if successful, false on failure.
   Stores the directory corresponding to the name into *DIRP,
   and the file name part into BASE_NAME. */
static bool
resolve_name_to_entry (const char *name,
                       struct dir **dirp, char base_name[NAME_MAX + 1])
{
    struct dir *dir = NULL;
    if (name[0] == '/' || thread_current ()->cwd == NULL) {
        /* if name starts with '/' or the thread doesn't have a current
         * working directory pointer saved, start with root directory */
        dir = dir_open_root ();
    } else {    /* otherwise, open current process's cwd */
        dir = dir_reopen (thread_current ()->cwd);
    }

    /* check value of dir; must not be NULL otherwise return false */
    if (dir == NULL) {
        dir_close (dir);
        *dirp = NULL;
        base_name[0] = '\0';
        return false;
    }

    char part[NAME_MAX + 1];        /* store next file part in get_next_part() */
    struct inode *inode = NULL;     /* dummy inode pointer */

    while (get_next_part (part, &name))   /* loop indefinitely through the name until exiting */
    {
        if (name[0] == '\0') {
            /* if the next part is empty, then the current directory is the
             * directory that contains the file */
            *dirp = dir;
            strlcpy (base_name, part, NAME_MAX + 1);
            return true;
        } else {    /* return value of get_next_part() is 1 */
            /* look up the next part in the current directory */
            if (!dir_lookup (dir, part, &inode)) {
                /* if the lookup fails, then return false */
                dir_close (dir);
                *dirp = NULL;
                base_name[0] = '\0';
                return false;
            }
            /* otherwise, close the current directory and open the next
             * directory */
            dir_close (dir);
            dir = dir_open (inode);
            if (dir == NULL) {
                /* if the open fails, then return false */
                dir_close (dir);
                *dirp = NULL;
                base_name[0] = '\0';
                return false;
            }
        }
    }

    /* handle case when return value of get_next_part() is 0 */
    *dirp = dir;
    base_name[0] = '\0';
    return true;
}

/* Resolves relative or absolute file NAME to an inode.
   Returns an inode if successful, or a null pointer on failure.
   The caller is responsible for closing the returned inode. */
static struct inode *
resolve_name_to_inode (const char *name)
{
    // check if we're at the root directory
    if (strcmp (name, "/") == 0)
    {
        return inode_open (ROOT_DIR_SECTOR);
    }
    struct dir *dir;
    char base_name[NAME_MAX + 1];
    if (!resolve_name_to_entry (name, &dir, base_name))
    {
        /* name of the file is not able to be found */
        return NULL;
    }
    struct inode *inode;

    // OLD CODE: DOES NOT WORK
    // if (!dir_lookup (dir, base_name, &inode))
    // {
    //     /* file does not exist */
    //     dir_close (dir);
    //     return NULL;
    // }

    // NEW CODE: WORKS
    dir_lookup (dir, base_name, &inode);
    dir_close (dir);

    return inode;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, enum inode_type type)
{
    struct dir *dir;    /* store parent directory information */
    char base_name[NAME_MAX + 1];
    bool success = resolve_name_to_entry (name, &dir, base_name);
    if (success)
    {
        block_sector_t inode_sector = 0;
        if (!free_map_allocate (&inode_sector)) {
            dir_close (dir);
            return false;
        }

        struct inode *inode = NULL;

        if (type == FILE_INODE) {   /* create new file */
            inode = file_create (inode_sector, initial_size);
            if (inode == NULL) {    
                free_map_release (inode_sector);
                dir_close (dir);
                return false;
            }
        } else if (type == DIR_INODE) { /* create new directory */
            inode = dir_create (inode_sector, inode_get_inumber (dir_get_inode (dir)));
            if (inode == NULL) {
                free_map_release (inode_sector);
                dir_close (dir);
                return false;
            }
        }

        bool added = dir_add (dir, base_name, inode_sector);
        if (!added) {
            inode_remove (inode);
            if (inode != NULL) {
                inode_close (inode);
            }
        } else {
            inode_close (inode);
        }

        dir_close (dir);
        return added;
    }
    return false;
}

/* TODO: Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name)
{
    // print the name of the file being opened
    // printf ("opening file: %s\n", name);
    if (strlen (name) == 0)
        return NULL;
    return resolve_name_to_inode (name);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
    if (strlen (name) == 0)
        return false;

    struct dir *dir;
    char base_name[NAME_MAX + 1];
    if (!resolve_name_to_entry (name, &dir, base_name))
    {
        /* otherwise, must handle file deletion */
        dir_close (dir);
        return false;
    }

    /* call dir_remove */
    // print the full directory you're trying to remove
    // printf ("currently looking at the directory: %s\n", name);
    bool success = dir_remove (dir, base_name);
    // print the value of success
    // printf ("success: %d\n", success);
    dir_close (dir);
    return success;
}

/* Change current directory to NAME.
   Return true if successful, false on failure. */
bool
filesys_chdir (const char *name)
{
    if (strlen (name) == 0)
        return false;

    struct inode *inode = resolve_name_to_inode (name);
    if (inode == NULL)
        return false;

    struct dir *dir = dir_open (inode);
    if (dir == NULL) {
        return false;
    }

    dir_close (thread_current ()->cwd);
    thread_current ()->cwd = dir;
    return true;
}

/* Formats the file system. */
static void
do_format (void)
{
  struct inode *inode;
  printf ("Formatting file system...");

  /* Set up free map. */
  free_map_create ();

  /* Set up root directory. */
  inode = dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);

  if (inode == NULL)
    PANIC ("root directory creation failed");
  inode_close (inode);

  free_map_close ();

  printf ("done.\n");
}
