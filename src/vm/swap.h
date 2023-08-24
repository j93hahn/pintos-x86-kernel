#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "vm/page.h"
#include "devices/block.h"

void swap_init (void);
void swap_in (struct page *p);
bool swap_out (struct page *p);

#endif
