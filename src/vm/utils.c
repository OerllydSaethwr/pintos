//
// Created by Raghav Khanna on 1/12/19.
//

#include "utils.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include <stdio.h>


bool is_stack_access(const void *ptr, void *esp)
{
  //printf("Verifying\n");
  /* Valid pointer if it's above  esp or 4 below (PUSH) or 32 below (PUSHA) */
  return (ptr >= (const void *) PHYS_BASE - MAX_STACK_SIZE && ptr < PHYS_BASE)
         && (ptr >= esp || ptr == esp - 4 || ptr == esp - 32);
}

void allocate_stack_page(void *upage) {
  struct supp_entry *supp = malloc(sizeof(supp));
  if (!supp)
    PANIC("Failed to allocate memory for supp entry for stack frame.\n");
  supp->location = LOADED;
  supp->writeable = true;
  supp->ptype = STACK;

  void *kernel_address = falloc_get_frame(upage)->kaddr;
  install_page (upage, kernel_address, supp->writeable);
}

void supp_dump(struct supp_entry *supp) {
  char *buf[] = {"STACK", "MMAP", "EXEC_CODE", "EXEC_DATA"};
  char *buf1[] = {"SWAP", "FSYS", "LOADED"};

  printf("-----------------------------------------------\n"
         "|| supp_entry at %p\n"
         "|| upage: %p\n"
         "|| file/bitmap_offset: %p\n"
         "|| offset: %u\n"
         "|| read_bytes: %u\n"
         "|| zero_bytes: %u\n"
         "|| writable: %u\n"
         "|| page_type: %s\n"
         "|| location: %s\n"
         "|| mapping: %p\n"
         "-----------------------------------------------\n",
         supp,
         supp->upage,
         supp->file,
         supp->offset,
         supp->read_bytes,
         supp->zero_bytes,
         supp->writeable,
         buf[supp->ptype],
         buf1[supp->location],
         supp->mapping);
}

void frame_dump(struct frame *frame) {
  printf("-----------------------------------------------\n"
         "frame at %p\n"
         "process: %p\n"
         "kpage: %p\n"
         "supp_entry: %p\n"
         "dirty: %u\n",
         frame,
         frame->process,
         frame->kaddr,
         frame->supp,
         pagedir_is_dirty(frame->process->pagedir, frame->supp->upage));
}