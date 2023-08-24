#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <string.h>
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/user/syscall.h"
#include "lib/stdio.h"
#include "lib/kernel/console.h"
#include "userprog/pagedir.h"
#include "filesys/inode.h"

/* declare all functions here */
static void syscall_handler (struct intr_frame *);
static void sys_halt (void);
static pid_t sys_exec (const char *cmdline);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int handle);
static int sys_read (int handle, void *buffer, unsigned size);
static int sys_write (int handle, void *buffer, unsigned size);
static void sys_seek (int handle, unsigned position);
static unsigned sys_tell (int handle);
static void sys_close (int handle);
static bool sys_chdir (const char *dir);
static bool sys_mkdir (const char *dir);
static bool sys_readdir (int fd, char *name);
static bool sys_isdir (int fd);
static int sys_inumber (int fd);
static bool put_user2 (uint8_t *udst, uint8_t byte);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static char *copy_in_string (const char *us);
static fd_t *get_fd_from_handle (int handle, struct thread *t);

/* current handle number to use for all new opened file descriptors
 *  0 & 1 defaulted for STDIN/STDOUT so start curr at 2
 */
int fd_curr = 2;

/* lock to maintain all file system interactions from the syscall handler */
static struct lock filesys_lock;

/* syscall initializer - calls the handler */
void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init (&filesys_lock);
}

// exit function for invalid memory access
static void
exit_invalid_mem_access (const void *vaddr)
{
    if (vaddr == NULL || vaddr < ((void *) 0x08048000) || !is_user_vaddr (vaddr))
        sys_exit (-1);
}

// check a buffer for invalid memory access
static void
check_buffer (const void *buffer, unsigned size)
{
    // unsigned i;
    // for (i = 0; i < size; i++) {
    //     exit_invalid_mem_access (buffer + i);
    //     void *kern_ptr = pagedir_get_page (thread_current ()->pagedir, buffer + i);
    //     if (kern_ptr == NULL)
    //         sys_exit(-1);
    // }

    exit_invalid_mem_access (buffer);
    void *kern_ptr = pagedir_get_page (thread_current ()->pagedir, buffer);
    if (kern_ptr == NULL)
        sys_exit(-1);
}

// retrieve the page pointer from a virtual address
static int
ptr_to_page (const void *vaddr)
{
    // check for invalid memory access
    exit_invalid_mem_access (vaddr);
    void *kern_ptr = pagedir_get_page (thread_current ()->pagedir, vaddr);
    if (kern_ptr == NULL) {
        sys_exit(-1);
    }
    return (int) kern_ptr;
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
    /* read syscall number from stack pointer */
    unsigned call_nr;
    copy_in (&call_nr, f->esp, sizeof(call_nr));

    /* args buffer to read in arguments from stack */
    int args[3];
    memset (args, 0, sizeof(args));
    // make sure the stack pointer is valid
    exit_invalid_mem_access (f->esp);

    // printf ("sys call number:k %d\n\n\n", call_nr);

    switch (call_nr) {
        case SYS_HALT: // SYS_HALT
            sys_halt ();
            break;
        case SYS_EXIT: // SYS_EXIT
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            sys_exit (args[0]);
            break;
        case SYS_EXEC: // SYS_EXEC
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            args[0] = ptr_to_page ((const void *) args[0]);
            f->eax = sys_exec ((const char *) args[0]);
            break;
        case SYS_WAIT: // SYS_WAIT
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            f->eax = sys_wait (args[0]);
            break;
        case SYS_CREATE: // SYS_CREATE
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
            args[0] = ptr_to_page ((const void *) args[0]);
            f->eax = sys_create ((const char *) args[0], (unsigned) args[1]);
            break;
        case SYS_REMOVE: // SYS_REMOVE
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            // args[0] = ptr_to_page ((const void *) args[0]);
            f->eax = sys_remove ((const char *) args[0]);
            break;
        case SYS_OPEN: // SYS_OPEN
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            // args[0] = ptr_to_page ((const void *) args[0]);
            // print args[0] in hex, print ptr_to_page, print result of is_user_vaddr
            // printf("here we go\n\n\n\n");
            ptr_to_page ((const void *) args[0]);
            // printf ("args[0] = %x, ptr_to_page = %x, is_user_vaddr = %d\n\n", args[0], ptr_to_page ((const void *) args[0]), is_user_vaddr ((const void *) args[0]));
            // if address is null or not a user address, exit
            f->eax = sys_open ((const char *) args[0]);
            break;
        case SYS_FILESIZE:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            f->eax = sys_filesize (args[0]);
            break;
        case SYS_READ:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 3);
            // check the buffer for valid memory access
            check_buffer((const void *)args[1], (unsigned)args[2]);
            // args[1] = ptr_to_page ((const void *) args[1]);
            f->eax = sys_read (args[0], (void *) args[1], (unsigned) args[2]);
            break;
        case SYS_WRITE:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 3);
            // check the buffer for valid memory access
            check_buffer((const void *)args[1], (unsigned)args[2]);
            f->eax = sys_write (args[0], (void *) args[1], (unsigned) args[2]);
            break;
        case SYS_SEEK:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
            sys_seek (args[0], (unsigned) args[1]);
            break;
        case SYS_TELL:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            f->eax = sys_tell (args[0]);
            break;
        case SYS_CLOSE:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            sys_close (args[0]);
            break;
        case SYS_MMAP:
        case SYS_MUNMAP:
            /* never implemented memory mapping system calls for project 3 */
            sys_exit(-1);
        case SYS_CHDIR:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            args[0] = ptr_to_page ((const void *) args[0]);
            f->eax = sys_chdir ((const char *) args[0]);
            break;
        case SYS_MKDIR:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            args[0] = ptr_to_page ((const void *) args[0]);
            f->eax = sys_mkdir ((const char *) args[0]);
            break;
        case SYS_READDIR:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
            args[1] = ptr_to_page ((const void *) args[1]);
            f->eax = sys_readdir (args[0], (char *) args[1]);
            break;
        case SYS_ISDIR:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            f->eax = sys_isdir (args[0]);
            break;
        case SYS_INUMBER:
            copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
            f->eax = sys_inumber (args[0]);
            break;
        default:    /* TODO: ask Daniar what to do on an invalid system call */
            // printf ("Invalid system call!");
            // thread_exit ();
            sys_exit(-1);
    }
}

/* Halt system call. */
static void
sys_halt (void)
{
    shutdown_power_off ();
}

/* Exit system call. */
void
sys_exit (int status)
{
    // printf ("TID OF EXITING THREAD: %d\n\n\n\n", thread_current ()->tid);
    // debug_backtrace_all ();
    struct thread *cur = thread_current ();
    printf ("%s: exit(%d)\n", cur->name, status);
    cur->exit_status = status;
    // printf("exit status: %d\n\n\n\n", thread_current ()->exit_status);
    // thread_yield ();
    while (cur->done == false) {
        // printf ("INSIDE THE WHILE LOOP\n\n\n\n\n\n\n");
        thread_yield ();
    }
    dir_close (cur->cwd);
    thread_exit ();
}

// get child
static struct thread *
get_child (tid_t tid)
{
    struct thread *t = thread_current ();
    struct list_elem *e;
    for (e = list_begin (&t->child_processes); e != list_end (&t->child_processes);
         e = list_next (e))
    {
        // printf ("INSIDE THE FOR LOOP\n\n\n\n\n\n\n");
        struct thread *child = list_entry (e, struct thread, child_elem);
        if (child->tid == tid) {
            // printf ("FOUND THE CHILD\n\n\n\n\n\n\n");
            return child;
        }
    }
    return NULL;
}

static struct thread *
get_thread_by_tid (tid_t tid)
{
    struct list_elem *e;
    for (e = list_begin (&all_processes); e != list_end (&all_processes);
         e = list_next (e)) {
        struct thread *t = list_entry (e, struct thread, process_elem);
        if (t->tid == tid) {
            return t;
        }
    }
    return NULL;
}

/* Exec system call. */
static pid_t
sys_exec (const char *cmdline)
{
    /* TODO */
    // printf ("hitting sys_exec() for cmdline: %s\n", cmdline);
    lock_acquire (&filesys_lock);
    tid_t tid = process_execute (cmdline);
    lock_release (&filesys_lock);
    // printf ("TID of child process: %d\n", tid);
    // struct thread *_t = get_thread_by_tid (tid);
    // if (_t == NULL) {
    //     printf ("ERROR\n\n\n\n\n");
    //     while (1) {};
    // }
    // list_push_back (&thread_current ()->child_processes, &_t->child_elem);

    struct list_elem *e;
    struct thread *t;
    for (e = list_begin (&thread_current ()->child_processes); e != list_end (&thread_current ()->child_processes);
         e = list_next (e)) {
        // child_process_t *child = list_entry (e, child_process_t, elem);
        struct thread *child = list_entry (e, struct thread, child_elem);
        if (child->tid == tid) {
            t = get_thread_by_tid (tid);
            // printf ("TID OF CHILD THREAD: %d\n\n\n\n\n\n\n", t->tid);
            if (t == NULL) {
                // printf ("ERROR\n\n\n\n\n");
                // lock_release (&filesys_lock);
                return -1;
            }

            // printf ("load_state: %d\n", t->load_state);
            if (t->load_state == -1) {
                // printf ("ERROR\n\n\n\n\n");
                // lock_release (&filesys_lock);
                return -1;
            }

            // printf ("TID OF CHILD THREAD: %d\n", t->tid);
            // TODO: Use condition variable instead of busy waiting
            // while (t->exit_status == RANDOM_NUM) {
            //     // printf ("exit status = %d\n\n\n\n", t->exit_status);
            //     thread_yield ();
            // };
            // printf ("exit status = %d\n\n\n\n", t->exit_status);
            // printf ("YESSIR\n\n\n\n\n");
            // printf ("exit status = %d\n\n\n\n", t->exit_status);
            /* we use -858993460 because we ran into an uninitialized variable bug */
            if (t->exit_status == -1) {
                // printf ("GOT HERE\n\n\n\n\n");
                // lock_release (&filesys_lock);
                return -1;
            }
            // printf ("ERROR\n\n\n\n\n");
            break;
        }
    }

    if (tid == TID_ERROR) {
        // lock_release (&filesys_lock);
        // printf ("ERROR\n\n\n\n\n");
        return -1;
    }
    // struct thread *child = get_child (tid);
    // if (child == NULL) {
    //     return -1;
    // }
    // if (!child->is_loaded) {
    //     sema_down (&child->sema_load);
    // }
    // printf ("tid = %d\n\n\n\n\n", tid);
    // lock_release (&filesys_lock);
    // while
    // printf ("ERROR\n\n\n\n\n");
    return tid;
}

/* Wait system call. */
static int
sys_wait (pid_t pid)
{
    struct thread *child = get_child (pid);
    if (child == NULL) {
        return -1;
    }
    int status = process_wait (pid);
    // printf ("STATUS: %d\n\n\n\n\n\n", status);
    return status;
}

/* Create system call. */
static bool
sys_create (const char *file, unsigned initial_size)
{
    lock_acquire (&filesys_lock);
    // char *kfile = copy_in_string (file);
    /* TODO: how do we call filesys_create here */
    bool success = filesys_create (file, initial_size, FILE_INODE);
    // palloc_free_page (kfile);
    lock_release (&filesys_lock);
    return success;
}

/* Remove system call. */
static bool
sys_remove (const char *file)
{
    lock_acquire (&filesys_lock);
    char *kfile = copy_in_string (file);
    bool success = filesys_remove (kfile);
    palloc_free_page (kfile);
    lock_release (&filesys_lock);
    return success;
}

/* Open system call. */
static int
sys_open (const char *file)
{
    lock_acquire (&filesys_lock);
    // char *kfile = copy_in_string (file);
    // if we're trying to open a null file name then give up
    if (file == NULL) {
        lock_release (&filesys_lock);
        return -1;
    }
    // if the pointer is bad then give up
    if (!is_user_vaddr (file)) {
        lock_release (&filesys_lock);
        return -1;
    }
    struct inode *inode = filesys_open (file);
    if (inode == NULL) {
        lock_release (&filesys_lock);
        return -1;
    }
    // palloc_free_page (kfile);


    /* malloc new file descriptor */
    fd_t *fd = (fd_t *) malloc (sizeof(fd_t));
    if (fd == NULL) {
        lock_release (&filesys_lock);
        return -1;
    }
    /* store file handle inside of disabled interrupts */
    enum intr_level old_level = intr_disable ();
    fd->handle = fd_curr++;
    intr_set_level (old_level);

    fd->type = inode_get_type (inode);
    if (fd->type == DIR_INODE) {
        /* directory inode type -> open up directory */
        fd->dir = dir_open (inode);
        fd->file = NULL;
    }
    else
    {
        fd->dir = NULL;
        struct file *f = file_open (inode);
        if (f == NULL) {
            lock_release (&filesys_lock);
            return -1;
        }
        fd->file = f;
        /* check if the file is executable */
        if (strcmp (thread_current ()->name, file) == 0) {
            file_deny_write (f);
            fd->deny_write = true;
        } else {
            fd->deny_write = false;
        }
    }

    list_push_back (&thread_current ()->open_files, &fd->file_elem);
    lock_release (&filesys_lock);
    return fd->handle;
}

/* Filesize system call. */
static int
sys_filesize (int handle)
{
    lock_acquire (&filesys_lock);

    /* extract file descriptor based on handle */
    fd_t *fd = get_fd_from_handle (handle, thread_current ());

    /* check if the file descriptor is valid */
    if (fd == NULL || fd->handle != handle) {
        return 0;
    }

    int size = file_length (fd->file);
    lock_release (&filesys_lock);

    return size;
}

/* Read system call. */
static int
sys_read (int handle, void *buffer, unsigned size)
{
    // printf ("    sys_read(): buffer value is %p\n", buffer);
    // bool ok = pagedir_get_page (thread_current ()->pagedir, buffer);

    if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size) || buffer == NULL) {
        sys_exit (-1);
    }

    unsigned size_cnt = size;

    /* store number of bytes read */
    int read = 0;

    /* cast buffer to char pointer */
    char *buf = buffer;

    // fd_t *fd = get_fd_from_handle (handle, thread_current ());

    // while (size > 0) {
    //     size_t remaining_read = PGSIZE - pg_ofs (buf);
    //     size_t read_bytes = size < remaining_read ? size : remaining_read;
    //     if (handle == STDIN_FILENO) {

    //     }
    // }

    /* read from the console */
    if (handle == STDIN_FILENO) {
        while (size > 0) {
            char c = input_getc ();
            // if (c == 0)
            //     break;
            bool try_put = put_user2 ((uint8_t *) buf, c);
            if (!try_put) {
                sys_exit (-1);
            }
            buf++;
            read++;
            size--;
        }
    } else {
        /* extract file descriptor based on handle */
        fd_t *fd = get_fd_from_handle (handle, thread_current ());

        /* check if the file descriptor is valid */
        if (fd == NULL || fd->handle != handle || fd->file == NULL) {
            read = -1;
            size = 0; /* don't enter the while loop! */
        }

        while (size > 0) { /* inspiration came from
                            * https://edstem.org/us/courses/37749/discussion/3092798?comment=7083125 */
            size_t remaining_read = PGSIZE - pg_ofs (buf);
            size_t read_bytes_amount = size < remaining_read ? size : remaining_read;
            off_t bytes_read = 0;

            lock_acquire (&filesys_lock);
            if (fd->type == FILE_INODE) {
                bytes_read = file_read (fd->file, buf, read_bytes_amount);
            } else {
                /* should not read from a directory inode */
                lock_release (&filesys_lock);
                return -1;
            }
            lock_release (&filesys_lock);

            /* if we read negative bytes, and read is 0, then exit */
            if (!read) {
                if (bytes_read < 0) {
                    read = -1;
                    break;
                }
            }
            // if (bytes_read < 0 && read == 0) {
            //     read = -1;
            //     break;
            // }

            read += bytes_read; /* increment total read pointer here */

            if ((off_t) read_bytes_amount != bytes_read) {
                /* read write did not match up */
                // read = -1;
                // printf ("read_total = %d\n     read_bytes_amount (%d) != bytes_read (%d)\n", read, read_bytes_amount, bytes_read);
                break;
            }

            /* advance buffer and subtract bytes read from size for while loop here */
            buf += bytes_read;
            size -= bytes_read;
        }
    }

    // ASSERT (read == size_cnt);

    return read;
}

/* Write system call. */
static int
sys_write (int handle, void *buffer, unsigned size)
{
    // if (handle != STDOUT_FILENO)
    //     printf ("    sys_write(): buffer value is %p\n", buffer);
    if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size) || buffer == NULL) {
        sys_exit (-1);
    }

    unsigned size_cnt = size;

    /* store number of bytes written */
    int written = 0;

    /* cast buffer to char pointer */
    uint8_t *buf = buffer;

    /* write to the console */
    if (handle == STDOUT_FILENO) {
        while (size > 0) {
            lock_acquire (&filesys_lock);
            putbuf (buf, 1);
            lock_release (&filesys_lock);
            buf++;
            written++;
            size--;

        }
        // putbuf (buffer, size);
        // written = size;
    } else {
        /* extract file descriptor based on handle */
        fd_t *fd = get_fd_from_handle (handle, thread_current ());

        /* check if the file descriptor is valid and write-able */
        if (fd == NULL || fd->handle != handle) {
            // printf ("GET HERE\n\n\n");
            written = 0; /* set written to 0 to pass rox tests */
            size = 0; /* don't enter the while loop! */
        }

        // if (fd->deny_write) {
        //     return 0;
        // }

        while (size > 0) { /* logic is directly copied from sys_read() */
            size_t remaining_write = PGSIZE - pg_ofs (buf);
            size_t write_bytes_amount = size < remaining_write ? size : remaining_write;
            off_t bytes_written;

            lock_acquire (&filesys_lock);
            if (fd->type == FILE_INODE) {
                bytes_written = file_write (fd->file, buf, write_bytes_amount);
            } else {
                /* cannot write to directory inode */
                lock_release (&filesys_lock);
                return -1;
            }
            lock_release (&filesys_lock);

            /* if we wrote negative bytes, and written is 0, then exit loop */
            // if (bytes_written < 0) {
            //     if (written == 0) {
            //         written = -1;
            //     }
            //     break;
            // }
            if (!written) {
                if (bytes_written < 0) {
                    written = -1;
                    break;
                }
            }

            // printf ("    sys_write(): bytes_written value is %d\n", bytes_written);

            written += bytes_written; /* increment total written pointer here */

            if (write_bytes_amount != bytes_written) {
                /* write amount expected did not match actual did not match up */
                // written = -1;
                // printf ("UH-OH\n");
                break;
            }

            // written += bytes_written; /* increment total written pointer here */

            /* advance buffer and subtract bytes written from size for while loop here */
            buf += bytes_written;
            size -= bytes_written;
        }
    }

    // ASSERT (written == size_cnt);

    // printf ("    sys_write(): written value is %d\n", written);
    return written;
}

/* Seek system call. */
static void
sys_seek (int handle, unsigned position)
{
    lock_acquire (&filesys_lock);

    /* extract file descriptor based on handle */
    fd_t *fd = get_fd_from_handle (handle, thread_current ());

    /* check if the file descriptor is valid */
    if (fd == NULL || fd->handle != handle) {
        return;
    }

    file_seek (fd->file, position);

    lock_release (&filesys_lock);
}

/* Tell system call. */
static unsigned
sys_tell (int handle)
{
    // while (!lock_try_acquire (&filesys_lock)) {
    //     thread_yield ();
    // }
    lock_acquire (&filesys_lock);

    /* extract file descriptor based on handle */
    fd_t *fd = get_fd_from_handle (handle, thread_current ());

    /* check if the file descriptor is valid */
    if (fd == NULL || fd->handle != handle) {
        return 0;
    }

    unsigned tell = file_tell (fd->file);

    lock_release (&filesys_lock);
    return tell;
}

/* Close system call. */
static void
sys_close (int handle)
{
    lock_acquire (&filesys_lock);
    // remove the file from the list of open files
    fd_t *fd = get_fd_from_handle (handle, thread_current ());
    if (fd == NULL || fd->handle != handle) {
        lock_release (&filesys_lock);
        return;
    }

    if (fd->type == FILE_INODE) {
        file_close (fd->file);
    } else {
        dir_close (fd->dir);
    }
    list_remove (&fd->file_elem);
    // unlock the file system
    lock_release (&filesys_lock);
}

/* Change directory system call. */
static
bool sys_chdir (const char *dir) {
    if (dir == NULL)
        return false;

    return filesys_chdir (dir);
}

/* Make directory system call */
static
bool sys_mkdir (const char *dir) {
    lock_acquire (&filesys_lock);
    // char *kfile = copy_in_string (file);
    /* TODO: how do we call filesys_create here */
    bool success = filesys_create (dir, 0, DIR_INODE);
    // palloc_free_page (kfile);
    lock_release (&filesys_lock);
    return success;
}

/* Read directory entry system call */
static
bool sys_readdir (int fd, char *name) {
    fd_t *file_desc = get_fd_from_handle (fd, thread_current ());
    if (file_desc == NULL || file_desc->dir == NULL) {
        return false;
    }

    return dir_readdir (file_desc->dir, name);
}

/* True if file descriptor contains directory; false otherwise */
static
bool sys_isdir (int fd) {
    fd_t *file_desc = get_fd_from_handle (fd, thread_current ());
    if (file_desc == NULL) {
        return false;
    }
    return (file_desc->dir != NULL);
}

/* Returns inode number of inode associated with file descriptor */
static
int sys_inumber (int fd) {
    fd_t *file_desc = get_fd_from_handle (fd, thread_current ());
    // this can be either a file or a dir, so we need to check both cases
    struct inode *inode;
    if (file_desc->type == FILE_INODE) {
        inode = file_get_inode (file_desc->file);
    } else {
        inode = dir_get_inode (file_desc->dir);
    }
    return inode_get_inumber (inode);
    // if (file_desc == NULL) {
    //     return -1;
    // }
    // printf("hitting this yes\n\n");
    // struct inode *inode = file_get_inode (file_desc->file);
    // printf("how about thuis\n\n");
    // return inode_get_inumber (inode);
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user2 (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

/* Copies a byte from user address USRC to kernel address DST.  USRC must
   be below PHYS_BASE.  Returns true if successful, false if a segfault
   occurred. Unlike the one posted on the p2 website, this one takes two
   arguments: dst, and usrc */
static inline bool
get_user2 (uint8_t *dst, const uint8_t *usrc)
{
    int eax;
    asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
        : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
    return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address DST.  Call
   thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
    uint8_t *dst = dst_;
    const uint8_t *usrc = usrc_;

    for (; size > 0; size--, dst++, usrc++) {
        if (usrc >= (uint8_t *) PHYS_BASE || !get_user2 (dst, usrc)) {
            sys_exit(-1);
        }
    }
}

/* Creates a copy of user string US in kernel memory and returns it as a
   page that must be **freed with palloc_free_page()**.  Truncates the string
   at PGSIZE bytes in size.  Call thread_exit() if any of the user accesses
   are invalid. */
static char *
copy_in_string (const char *us)
{
    char *ks;

    ks = palloc_get_page (0);
    if (ks == NULL) {
        thread_exit();
    }

    for (size_t length = 0; length < PGSIZE; length++) {
        if (us >= (char *) PHYS_BASE ||
            !get_user2 ((uint8_t *) ks + length, (uint8_t *) us + length)) {
            thread_exit ();
        }
        if (ks[length] == '\0') {
            break;
        }
    }

    return ks;
}

/* Returns the file descriptor associated with the given file handle. */
static fd_t *
get_fd_from_handle (int handle, struct thread *t)
{
    struct list_elem *e;
    fd_t *fd = NULL;
    for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
         e = list_next (e)) {
        fd = list_entry (e, fd_t, file_elem);
        if (fd->handle == handle) {
            break;
        }
    }
    return fd;
}
