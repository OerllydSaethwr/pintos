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
#include "threads/interrupt.h"
#include  "lib/string.h"
#include "userprog/process.h"

struct swap_table swap_table;

static inline size_t find_free_sector(void);
struct lock swap_table_lock;

extern struct semaphore eviction_sema;

void swap_init() {
  lock_init(&swap_table_lock);
  struct block *swap_device = block_get_role(BLOCK_SWAP);
  swap_table.bitmap = bitmap_create(block_size(swap_device) / 8);
  swap_table.block_device = swap_device;
}

void evict_frame() {
  enum page_type type;
  struct supp_entry *evicted_supp;
  struct frame *frame;
  frame = frame_to_evict();
  if (pagedir_is_dirty(frame->process->pagedir, frame->supp->upage)) {
    frame->supp->dirty = true;
  }

  ASSERT(frame->supp);
  type = frame->supp->ptype;
  switch (type){
    case STACK:
      evicted_supp = swap_to_swap(frame);
      break;
    case MMAP:
      evicted_supp = swap_to_file_or_discard(frame);
      break;
    case EXEC_CODE:
      evicted_supp = swap_to_discard(frame);
      break;
    case EXEC_DATA:
      evicted_supp = swap_to_discard_or_swap(frame);
      break;
    default:
      PANIC("Shouldn't get here.\n");
  }

  pagedir_clear_page(frame->process->pagedir, frame->supp->upage);
  pagedir_set_page (frame->process->pagedir, frame->supp->upage, frame->supp,
                    frame->supp->writeable, FAKE);

  falloc_free_frame(frame->kaddr);
  sema_up(&evicted_supp->eviction_sema);
}

struct supp_entry *swap_to_discard_or_swap(struct frame *frame) {
  return (frame->supp->dirty ? swap_to_swap(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_file_or_discard(struct frame *frame) {
  return (frame->supp->dirty ? swap_to_file(frame) : swap_to_discard(frame));
}

struct supp_entry *swap_to_discard(struct frame *frame) {
  frame->supp->location = FSYS;
  return frame->supp;
}

struct supp_entry *swap_to_swap(struct frame *frame) {
  uint32_t *kaddr = frame->kaddr;
  struct supp_entry *supp = frame->supp;
  lock_acquire(&swap_table_lock);
  size_t free_sector = find_free_sector();
  lock_release(&swap_table_lock);
  if (free_sector == BITMAP_ERROR) {
    PANIC("Swap is full.\n");
  }

  for (uint32_t i = 0; i < PGSIZE; i += BLOCK_SECTOR_SIZE) {
    block_write(swap_table.block_device, (block_sector_t) free_sector * 8 + (i / BLOCK_SECTOR_SIZE), frame->kaddr + i);
  }

  supp->location = SWAP;
  supp->file = (struct file *) free_sector;

  return supp;
}

struct supp_entry *swap_to_file(struct frame *frame) {
  struct supp_entry *supp = frame->supp;
  struct file_descriptor *fd = hash_entry(supp->mapping, struct file_descriptor, thread_hash_elem);
  lock_the_filesys();
  file_seek(fd->actual_file, supp->offset);
  file_write(fd->actual_file, frame->kaddr, supp->read_bytes);
  unlock_the_filesys();
  supp->location = FSYS;
  return supp;
}

static inline size_t find_free_sector(void){
  return bitmap_scan_and_flip(swap_table.bitmap, 0, 1, 0);
}

bool load_from_swap(struct supp_entry *supp) {
  ASSERT(supp->location == SWAP);

  struct frame *frame = falloc_get_frame(supp->upage);

  size_t block_index = (size_t) supp->file;

  for (uint32_t i = 0; i < PGSIZE; i += BLOCK_SECTOR_SIZE) {
    block_read(swap_table.block_device, (block_sector_t) block_index * 8 + i / BLOCK_SECTOR_SIZE, frame->kaddr + i);
  }

  lock_acquire(&swap_table_lock);
  bitmap_scan_and_flip(swap_table.bitmap, block_index, 1, 1);
  lock_release(&swap_table_lock);
  install_page(supp->upage, frame->kaddr, supp->writeable);
  supp->location = LOADED;
  frame->supp = supp;

  return true;
}


