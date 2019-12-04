//
// Created by dmv18 on 03/12/2019.
//

#ifndef PINTOS_08_SWAP_H
#define PINTOS_08_SWAP_H

#include <bitmap.h>
#include "frame.h"
struct swap_table {
  struct bitmap *bitmap;
  struct block *block_device;
};

void swap_init();
struct supp_entry* evict(struct frame *frame);
struct supp_entry *swap_to_swap(struct frame *);
struct supp_entry *swap_to_file(struct frame *);
struct supp_entry *swap_to_discard_or_swap(struct frame *);
struct supp_entry *swap_to_file_or_discard(struct frame *);
struct supp_entry* swap_to_discard(struct frame *);

#endif //PINTOS_08_SWAP_H
