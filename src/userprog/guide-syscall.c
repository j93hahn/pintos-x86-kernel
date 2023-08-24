

// Here's some pieces of code segment that might be helpful.
// Again, you don't have to follow this approach.
// You can design this anyway you like as long as you pass
// the checks



/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  ...;
  unsigned call_nr;
  int args[3]; // It's 3 because that's the max number of arguments in all syscalls.

  copy_in (&call_nr, f->esp, sizeof call_nr); // See the copy_in function implementation below.

  ...;

  // copy the args (depends on arg_cnt for every syscall).
  // note that if the arg passed is a pointer (e.g. a string),
  // then we just copy the pointer here, and you still need to
  // call 'copy_in_string' on the pointer to pass the string
  // from user space to kernel space
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * arg_cnt);

  f->eax = (the syscall that you should call);

}


/* Exec system call. */
static int
sys_exec (const char *ufile)
{
  ...; process_execute(...); ...;
}

/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size)
{
  ...;
  char *kfile = copy_in_string (ufile);
  ...;
  bool ok = filesys_create (kfile, initial_size);
  ...;
  return ok;
}



/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size)
{
  ...;
  struct file_descriptor *fd = lookup_fd(handle);
  int sizeToWrite = size;

  while (sizeToWrite > 0) {

    ...;

    if (handle == STDOUT_FILENO)
      {
	putbuf (usrc, write_amount);
	retval = write_amt;
      }
    else
      {
	retval = file_write (fd->file, usrc, write_amount);
      }

    ...;

    sizeToWrite -= retval;

  }

  ...;
}




/* Copies a byte from user address USRC to kernel address DST.  USRC must
   be below PHYS_BASE.  Returns true if successful, false if a segfault
   occurred. Unlike the one posted on the p2 website, this one takes two
   arguments: dst, and usrc */

static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}


/* Writes BYTE to user address UDST.  UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */

static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}



/* Copies SIZE bytes from user address USRC to kernel address DST.  Call
   thread_exit() if any of the user accesses are invalid. */

static void copy_in (void *dst_, const void *usrc_, size_t size) {

  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
      thread_exit ();
}



/* Creates a copy of user string US in kernel memory and returns it as a
   page that must be **freed with palloc_free_page()**.  Truncates the string
   at PGSIZE bytes in size.  Call thread_exit() if any of the user accesses
   are invalid. */
static char *
copy_in_string (const char *us)
{
  char *ks;
  size_t length;

  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  for (...)
    {

      ...;
      // call get_user() until you see '\0'
      ...;

    }

  return ks;

  // don't forget to call palloc_free_page(..) when you're done
  // with this page, before you return to user from syscall
}
