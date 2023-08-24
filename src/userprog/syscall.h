#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/kernel/list.h"
#include "filesys/directory.h"
#include "filesys/inode.h"

void syscall_init (void);
void sys_exit (int status);

/* struct to bind a file descriptor to an open file */
typedef struct file_descriptor {
    int handle;                     /* file descriptor handle */
    struct file *file;              /* file pointer */
    struct list_elem file_elem;     /* list element */
    bool deny_write;                /* deny write flag */

    /* this Ed post recommends adding these parameters to our fd_t struct
     * https://edstem.org/us/courses/37749/discussion/3150048 */
    struct dir *dir;                /* directory pointer */
    enum inode_type type;           /* inode type */
} fd_t;

#endif /* userprog/syscall.h */
