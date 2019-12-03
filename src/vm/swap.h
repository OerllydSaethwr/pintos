//
// Created by dmv18 on 03/12/2019.
//

#ifndef PINTOS_08_SWAP_H
#define PINTOS_08_SWAP_H

#include <bitmap.h>

struct swap_table {
  struct bitmap *bitmap;
  struct block *block_device;
};

void swap_init();

#endif //PINTOS_08_SWAP_H
