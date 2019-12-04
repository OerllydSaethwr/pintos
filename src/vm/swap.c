//
// Created by dmv18 on 03/12/2019.
//

#include "devices/block.h"
#include "swap.h"
#include "userprog/pagedir.h"
#include "frame.h"

struct swap_table swap_table;

void swap_init() {
  struct block *swap_device = block_get_role(BLOCK_SWAP);
  swap_table.bitmap = bitmap_create(block_size(swap_device));
  swap_table.block_device = swap_device;
}


struct supp_entry* evict(struct frame *frame) {


}



