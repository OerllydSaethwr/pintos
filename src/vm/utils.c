//
// Created by Raghav Khanna on 1/12/19.
//

#include "utils.h"
#include "userprog/pagedir.h"
#include "frame.h"
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