//
// Created by vishwam on 02/12/2019.
//

#ifndef PINTOS_08_MMAP_H
#define PINTOS_08_MMAP_H

#include <hash.h>
#include <userprog/pagedir.h>
#include "userprog/syscall.h"

struct mmap_table {
  struct hash mmap_table;
  mapid_t map_id;
};

struct mmap_entry {
  struct hash_elem hash_elem;
  uint32_t location_of_file;
  mapid_t map_id;
};

void mmap_table_init(void);
void mmap_table_free(void);


static struct mmap_table *mmap_table;

#endif //PINTOS_08_MMAP_H
