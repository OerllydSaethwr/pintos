//
// Created by dmv18 on 03/12/2019.
//

#include "devices/block.h"
#include "swap.h"
#include "userprog/pagedir.h"
#include "frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"
struct swap_table swap_table;

void swap_init() {
  struct block *swap_device = block_get_role(BLOCK_SWAP);
  swap_table.bitmap = bitmap_create(block_size(swap_device));
  swap_table.block_device = swap_device;
}



struct supp_entry* evict(struct frame *frame) {
  page_type type = frame->page_type;
  switch (type){
    case STACK:
      return swap_to_swap(frame);
    case MMAP:
      return swap_to_file_or_discard(frame);
    case EXEC_CODE:
      return swap_to_discard(frame);
    case EXEC_DATA:
      return swap_to_discard_or_swap(frame);
  }
}


struct supp_entry *swap_to_discard_or_swap(struct frame *frame) {
  return (pagedir_is_dirty(thread_current()->pagedir, frame->uaddr) ? swap_to_swap(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_file_or_discard(struct frame *frame) {
  return (pagedir_is_dirty(thread_current()->pagedir, frame->uaddr) ? swap_to_file(frame) : swap_to_discard(frame));
}

struct supp_entry* swap_to_discard(struct frame *frame){
  uint32_t  *kaddr = frame->kaddr;

  falloc_free_frame(kaddr);
  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
  supp->location = FSYS;
  supp->file = frame->file;
  return supp;
}

struct supp_entry *swap_to_swap(struct frame *frame) {

  return NULL;
}

struct supp_entry *swap_to_file(struct frame *frame) {
  if (pagedir_is_dirty(thread_current()->pagedir, frame->uaddr)) {

  }
  return NULL;
}




