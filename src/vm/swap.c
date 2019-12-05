//
// Created by dmv18 on 03/12/2019.
//

#include "filesys/file.h"
#include "devices/block.h"
#include "swap.h"
#include "userprog/pagedir.h"
#include "frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include <stdio.h>
#include  "lib/string.h"

struct swap_table swap_table;

static inline size_t find_free_sector(void);


void swap_init() {
  struct block *swap_device = block_get_role(BLOCK_SWAP);
  swap_table.bitmap = bitmap_create(block_size(swap_device) / 8);
  swap_table.block_device = swap_device;
}

struct supp_entry *evict_frame(struct frame *frame) {

  list_remove(&frame->list_elem);

  enum page_type type;
  type = frame->supp->ptype;
  switch (type){
    case STACK:
      return swap_to_swap(frame);
    case MMAP:
      return swap_to_file_or_discard(frame);
    case EXEC_CODE:
      return swap_to_discard(frame);
    default:
      return swap_to_discard_or_swap(frame);
  }
}

struct supp_entry *swap_to_discard_or_swap(struct frame *frame) {
  return (pagedir_is_dirty(frame->process->pagedir, frame->supp->upage) ? swap_to_swap(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_file_or_discard(struct frame *frame) {
  return (pagedir_is_dirty(frame->process->pagedir, frame->supp->upage) ? swap_to_file(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_discard(struct frame *frame) {
  uint32_t  *kaddr = frame->kaddr;

  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
  supp->location = FSYS;
  supp->file = frame->supp->file;
  supp->writeable = pagedir_is_writeable(frame->process->pagedir, frame->supp->upage);
  falloc_free_frame(kaddr);
  return supp;
}

struct supp_entry *swap_to_swap(struct frame *frame) {
  uint32_t *kaddr = frame->kaddr;
  size_t free_sector = find_free_sector();
  if (free_sector == BITMAP_ERROR) {
    PANIC("Swap is full\n");
  }
  for (uint32_t i = 0; i < PGSIZE; i += BLOCK_SECTOR_SIZE) {
    uint32_t buffer[BLOCK_SECTOR_SIZE];
    memcpy(buffer, kaddr + i, BLOCK_SECTOR_SIZE);
    block_write(swap_table.block_device, (block_sector_t) free_sector* 8 + i / BLOCK_SECTOR_SIZE, buffer);
  }

  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
  supp->location = SWAP;
  supp->file = (void *) free_sector;
  supp->writeable = true;
  supp->read_bytes = PGSIZE;
  falloc_free_frame(kaddr);
  return supp;
}

struct supp_entry *swap_to_file(struct frame *frame) {
  struct file_descriptor *fd = hash_entry(frame->supp->mapping,struct file_descriptor, thread_hash_elem);
  uint32_t ofs = (uint32_t) frame->supp->upage - (uint32_t) fd->upage;
  uint32_t num_of_bytes = file_length(frame->supp->file) - ofs;
  file_seek(frame->supp->file, ofs);
  file_write(frame->supp->file, frame->supp->upage, num_of_bytes);

  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
  supp->location = FSYS;
  supp->file = frame->supp->upage;
  supp->writeable = true;
  falloc_free_frame(frame->kaddr);
  return supp;
}

static inline size_t find_free_sector(void){
  return bitmap_scan_and_flip(swap_table.bitmap, 0, 1, 0);
}


