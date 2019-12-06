//
// Created by Raghav Khanna on 1/12/19.
//
#include "userprog/pagedir.h"
#include "vm/frame.h"
#ifndef UTILS
#define UTILS

#include "lib/stdbool.h"
#define MAX_STACK_SIZE 10485760  /* 10 MiB hard maximum for stack*/


bool is_stack_access(const void *ptr, void *esp);

void allocate_stack_page(void *upage);

enum page_type {
  STACK,
  MMAP,
  EXEC_CODE,
  EXEC_DATA
};

void supp_dump(struct supp_entry *supp);
void frame_dump(struct frame *frame);
#endif
