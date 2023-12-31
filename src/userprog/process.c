#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
    char *fn_copy;
    tid_t tid;
    // struct dir *cwd = thread_current ()->cwd;
    /* Make a copy of FILE_NAME.
        Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page (0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy (fn_copy, file_name, PGSIZE);

    char *fn_copy2 = palloc_get_page (0);
    if (fn_copy2 == NULL)
        return TID_ERROR;
    strlcpy (fn_copy2, file_name, PGSIZE);
    char *name, *save_ptr;
    name = strtok_r (fn_copy2, " ", &save_ptr);

    /* Create a new thread to execute FILE_NAME. */
    // child_process_t *child = (child_process_t *) malloc (sizeof (child_process_t));
    struct thread *child = (struct thread *) malloc (sizeof (struct thread));
    child->name2 = fn_copy;
    child->cwd = thread_current ()->cwd;    /* child process inherits parent
                                             * process's cwd */
    // child->exit_status = RANDOM_NUM;
    child->tid = tid = thread_create (name, PRI_DEFAULT, start_process, child);
    // printf ("child->tid: %d\n\n\n\n\n\n", child->tid);
    if (tid == TID_ERROR) {
        free (child);
        palloc_free_page (fn_copy);
    }

    /* add child process to current thread's child_processes list */
    list_push_back (&thread_current ()->child_processes, &child->child_elem);

    /* wait until child process is loaded */
    while (child->load_state == 0) {
        // sema_down (&child->sema_load);
        thread_yield ();
    }

    palloc_free_page (fn_copy2);
    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *child_)
{
    // child_process_t *child = child_;
    struct thread *child = child_;

    /* file_name stores fn_copy from process_execute() which is mutable */
    char *file_name = child->name2;
    struct intr_frame if_;
    bool success;

    // thread_current ()->cwd = child->cwd;
    /* Initialize interrupt frame and load executable. */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load (file_name, &if_.eip, &if_.esp);

    // if success, set current thread's load status to true
    if (success) {
        child->load_state = 1;
    } else {
        child->load_state = -1;
    }
    // sema_up (&child->sema_load);

    /* If load failed, quit. */
    palloc_free_page (file_name);
    if (!success) {
        // free (child);
        // thread_current ()->exit_status = -1;
        // thread_exit ();
        sys_exit (-1);
    }

    /* Start the user process by simulating a return from an
        interrupt, implemented by intr_exit (in
        threads/intr-stubs.S).  Because intr_exit takes all of its
        arguments on the stack in the form of a `struct intr_frame',
        we just point the stack pointer (%esp) to our stack frame
        and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
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

static struct thread *
get_thread_child(struct thread *parent, tid_t tid)
{
    struct list_elem *e;
    for (e = list_begin (&parent->child_processes); e != list_end (&parent->child_processes);
         e = list_next (e)) {
        struct thread *child = list_entry (e, struct thread, child_elem);
        if (child->tid == tid) {
            return child;
        }
    }
    return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{

    if (child_tid == TID_ERROR) {
        // printf ("HITTING HERE\n\n\n\n");
        return -1;
    }

    struct list_elem *e;
    struct thread *t;
    for (e = list_begin (&thread_current ()->child_processes); e != list_end (&thread_current ()->child_processes);
         e = list_next (e)) {
        // child_process_t *child = list_entry (e, child_process_t, elem);
        struct thread *child = list_entry (e, struct thread, child_elem);
        if (child->tid == child_tid) {
            t = get_thread_by_tid (child_tid);
            if (t == NULL) {
                // printf ("t is null\n\n\n\n");
                return child->exit_status;
            }
            // TODO: Use condition variable instead of busy waiting
            while (t->exit_status == RANDOM_NUM) {
                // printf ("waiting for child to exit\n\n\n\n\n");
                thread_yield ();
            };
            // printf ("child exit status: %d\n\n\n\n\n", t->exit_status);
            list_remove (&child->child_elem);
            int exit_status = t->exit_status;
            t->done = true;
            return t->exit_status;
        }
    }

    // if (child_tid == TID_ERROR) {
    //     return -1;
    // }

    // struct thread *cur = thread_current ();
    // struct thread *child = NULL;
    // if (child_tid == TID_ERROR || list_empty(&cur->child_processes)) {
    //     return -1;
    // }
    // child = get_thread_child (cur, child_tid);
    // if (child == NULL) {
    //     return -1;
    // }
    // // remove the child from the child_processes list
    // list_remove (&child->child_elem);
    // sema_down (&child->sema_wait);
    // return child->exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
    struct thread *cur = thread_current ();
    struct thread *child = NULL;
    list_remove (&cur->process_elem);

    /* Free all file descriptors owned by current thread. */
    struct list_elem *e;
    for (e = list_begin (&cur->open_files); e != list_end (&cur->open_files);
         e = list_remove (e)) {
        fd_t *fd = list_entry (e, fd_t, file_elem);
        file_close (fd->file);
        free (fd);
    }

    /* Remove all child processes. */
    // for (e = list_begin (&cur->child_processes); e != list_end (&cur->child_processes);
    //      e = list_remove (e)) {
    //     //  child = list_entry (e, child_process_t, elem);
    //     child = list_entry (e, struct thread, child_elem);
    // }

    uint32_t *pd;

    /* TODO: close file */

    /* Destroy the current process's page directory and switch back
        to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
            cur->pagedir to NULL before switching page directories,
            so that a timer interrupt can't switch back to the
            process page directory.  We must activate the base page
            directory before destroying the process's page
            directory, or our active page directory will be one
            that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate (NULL);
        pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Make a copy of FILE_NAME to avoid const char * limitations */
  char *argv = palloc_get_page (0);
  if (argv == NULL)
    return TID_ERROR;
  strlcpy (argv, file_name, PGSIZE);

  /* split filename from argv[] */
  char *filename = strtok_r (argv, " ", &argv);

  /* Open executable file. */
  file = file_open (filesys_open (filename));
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  file_deny_write (file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry; // what is *eip supposed to do?

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *cmdline)
{
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        uint8_t *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
        success = install_page (upage, kpage, true);
        if (success) {
            /* set stack pointer to PHYS_BASE */
            *esp = PHYS_BASE;

            /* ensure size of cmdline is <= PGSIZE */
            if (strlen(cmdline) > PGSIZE) {
                /* for now, return NULL is fine but implement syscall later */
                return NULL;
            }

            /* parse cmdline for each arg */
            char *token, *save_ptr;                 /* for strtok_r */
            int argc = 0;                           /* number of arguments */
            int total = 0;                          /* total byte length of arguments */
            int *arg_lens = (int *)                 /* array of argument lengths */
                malloc(sizeof(int) * 255);
            char **tokStorage = (char **)           /* array of tokens */
                malloc(sizeof(char *) * 255);

            /* TODO: ask Daniar for heap allocation bounds & failures */
            if (arg_lens == NULL) {
                PANIC ("process.c: setup_stack() --> failed arg_lens heap allocation\n");
            }
            if (tokStorage == NULL) {
                PANIC ("process.c: setup_stack() --> failed tokStorage heap allocation\n");
            }

            for (token = strtok_r (cmdline, " ", &save_ptr); token != NULL;
                token = strtok_r (NULL, " ", &save_ptr)) {
                /* calculate size of each token, +1 for NUL terminator */
                int tokLen = strlen(token) + 1;

                /* store info about arg len and address */
                arg_lens[argc] = tokLen;
                tokStorage[argc] = token;

                /* increment total number of bytes stored and arg count */
                total += sizeof(char) * tokLen;
                argc++;
            }

            /* push args in reverse order onto the stack */
            uintptr_t *addresses = (uintptr_t *)    /* array of argument addresses on stack */
                malloc(sizeof(uintptr_t) * argc);
            if (addresses == NULL) {
                PANIC ("process.c: setup_stack() --> failed addresses heap allocation\n");
            }

            for (int i = argc - 1; i >= 0; i--) {
                /* decrement stack pointer & copy token to stack */
                *esp -= sizeof(char) * arg_lens[i];
                memcpy (*esp, tokStorage[i], arg_lens[i]);

                /* store addresses of each argv operand */
                addresses[i] = (uintptr_t) *esp;
            }

            /* apply word alignment here */
            if (total % 4 == 1) {
                *esp -= sizeof(char) * 3;
                memset (*esp, (uint8_t) 0, 3);
            } else if (total % 4 == 2) {
                *esp -= sizeof(char) * 2;
                memset (*esp, (uint8_t) 0, 2);
            } else if (total % 4 == 3) {
                *esp -= sizeof(char);
                memset (*esp, (uint8_t) 0, 1);
            } // else - stack pointer is already word-aligned

            /* push argv[n] for n = {argc..0} onto the stack -- (char *) */
            for (int i = argc; i >= 0; i --) {
                if (i == argc) {
                    /* if i == argc, push all 0's onto the stack */
                    *esp -= sizeof(char) * 4;
                    memset (*esp, (uint8_t) 0, 4);
                } else {
                    /* reverse byte order for little-endianness */
                    uint64_t addr = addresses[i]; // cast to uint64_t for bit manip
                    for (int j = 0; j < 4; j++) {
                        *esp -= sizeof(char);
                        memset (*esp, (addr >> (8 * (3 - j))) & 0xff, 1);
                    }
                }
            }

            /* push argv[0]'s address onto the stack -- (char **) */
            uint64_t argv_addr = (uintptr_t) *esp;
            for (int j = 0; j < 4; j++) {
                *esp -= sizeof(char);
                memset (*esp, (argv_addr >> (8 * (3 - j))) & 0xff, 1);
            }

            /* push argc onto the stack */
            if (argc <= 255) {
                *esp -= sizeof(char) * 4;
                memset (*esp, argc, 1);
            } else {
                PANIC ("process.c: setup_stack() --> argc is too large\n");
            }

            /* push return address onto the stack */
            *esp -= sizeof(char) * 4;
            memset (*esp, (uint8_t) 0, 4);

            /* free all heap-allocated memory */
            free (arg_lens);
            free (tokStorage);
            free (addresses);

            /* test implementation of pushing onto the stack */
            // hex_dump((uintptr_t) *esp, *esp, PHYS_BASE - *esp, true);
        } else {
            palloc_free_page (kpage);
        }
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
