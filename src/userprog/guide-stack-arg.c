

// Dear all,

// Here are some tips about how to implement stack setup and parsing
// arguments:

// I. By default, file name is passed to load function. To parse your
// command line, you can pass command line to load, and inside load
// you extract file name and args.


// II. Inside setup_stack():
// You should set esp to PHYS_BASE, and setup
// stack and parse the command line string like this:

// 1. You should check that size of command line string is not
// larger than PGSIZE. and if it is larger you should return null.

// 2. Then you push command line string onto stack in kpage using this
// memory copy function (we provide a wrapped push function below,
// but feel free to use your own implementation):

//   memcpy(kpage + PGSIZE - commandline_size, command line, commandline_size)

// It copies the string to stack in kpage starting from kpage + PGSIZE
// address.


// 3. Now you should start to parse the arguments from copied string in
// stack using strtok_r function and " " delimiter.

// Calculate the mapped address of each parsed argument in user page
// like this:

void *user_arg = userpage + (parsed_arg - (char *) kpage);

// And push the user_arg's address to kpage stack:

//   memcpy(kpage + PGSIZE- size of (&parsed_arg))


// 4. After pushing all arguments, you need to reverse the order of
// arguments, because they have been pushed in reversed order. (Use a
// simple reverse function to reverse bytes' places in kpage stack.)

// Again you should push the result of reverse function to the kpage:

//   memcpy(kpage+PGSIZE-size of (result of reverse))

// 5. Finally you should push the address of user page (PHYSBASE) and
// also number of arguments to the kpage stack. Also, update
// the esp with the top of the stack pointer.

// 6. You may want to use hex_dump() function to debug your stack.

// III. To Handle Dereferences:
// Inside exception.c: page_fault function,
// you should check if the address is not accessible for user, do the
// following jobs and return:

if (!user)
    {
      f->eip = (void (*) (void)) f->eax;
      f->eax = 0;
      return;
    }


// IV. Helper Functions
// You need to put some data (args, pointers, etc.)
// to the stack in the kernel page in word-alignment.
// (See Pintos Guide Section 3.5.1)
// Below is a wrapped memcpy helper function that you can use.
// It's a little bit complex, because it passes pointer by reference
// (i.e. pointer to pointer).
// Feel free to use your own implementation.
// Offset (ofs) will be automatically modified inside the push() function.


static void *
push (uint8_t *kpage, size_t *ofs, const void *buf, size_t size)
{
  size_t padsize = ROUND_UP (size, sizeof (uint32_t));
  if (*ofs < padsize)
    return NULL;

  *ofs -= padsize;
  memcpy (kpage + *ofs + (padsize - size), buf, size);
  return kpage + *ofs + (padsize - size);
}

// Here's some sample of push() usages:

const char *cmd_line = ...; // the user command line
push (kpage, &offset, cmd_line, strlen (cmd_line) + 1);

void *uarg = ...; // a memory address to an argument
push (kpage, &offset, &uarg, sizeof uarg);

int argc = ...;
push (kpage, &offset, &argc, sizeof argc)
