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
  return (pagedir_is_dirty(frame->process->pagedir, frame->uaddr) ? swap_to_swap(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_file_or_discard(struct frame *frame) {
  return (pagedir_is_dirty(frame->process->pagedir, frame->uaddr) ? swap_to_file(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_discard(struct frame *frame){
  uint32_t  *kaddr = frame->kaddr;

  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
  supp->location = FSYS;
  supp->file = frame->file;
  supp->writeable = pagedir_is_writeable(frame->process->pagedir, frame->uaddr);
  falloc_free_frame(kaddr);
  return supp;
}

struct supp_entry *swap_to_swap(struct frame *frame) {
  uint32_t  *kaddr = frame->kaddr;
  size_t free_sector = find_free_sector();
  for(uint32_t i = 0; i < PGSIZE; i += BLOCK_SECTOR_SIZE){
    uint32_t  buffer[BLOCK_SECTOR_SIZE];
    memcpy(buffer, kaddr + i, BLOCK_SECTOR_SIZE);
    block_write(swap_table.block_device, (block_sector_t) free_sector* 8 + i / BLOCK_SECTOR_SIZE, buffer );
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
//    uint32_t ofs = (uint32_t) frame->uaddr - (uint32_t) frame->m_entry->location_of_file;
//    uint32_t num_of_bytes = file_length(frame->m_entry->file) - ofs;
//    file_seek(frame->m_entry->file, ofs);
//    file_write(frame->m_entry->file, frame->uaddr, num_of_bytes);
//
//  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
//  supp->location = FSYS;
//  supp->file = frame->file;
//  supp->writeable = true;
//  falloc_free_frame(frame->kaddr);
  return NULL;
}

static inline size_t find_free_sector(void){
  return bitmap_scan_and_flip(swap_table.bitmap, 0, 1, 0);
}


