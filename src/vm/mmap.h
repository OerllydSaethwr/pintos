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
  int map_id;
};

struct mmap_entry {
  struct hash_elem hash_elem;
  struct supp_entry* supp_entry;
  uint32_t location_of_file;
  mapid_t map_id;
};

void mmap_table_init(void);
void mmap_table_free(void);


extern struct mmap_table *mmap_table;

#endif //PINTOS_08_MMAP_H
