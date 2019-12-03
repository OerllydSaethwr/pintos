//
// Created by vishwam on 02/12/2019.
//

#ifndef PINTOS_08_MMAP_H
#define PINTOS_08_MMAP_H

#include <hash.h>
#include <userprog/pagedir.h>
#include "userprog/syscall.h"

struct mmap_entry {
  struct hash_elem hash_elem;
  void *location_of_file;
  mapid_t map_id;
  struct file *file;
  uint32_t size;
};

void mmap_table_init(struct hash *);
mapid_t allocate_map_id(void);
void m_unmap(mapid_t);
void unmap_hash (struct hash_elem *, void * UNUSED);

#endif //PINTOS_08_MMAP_H
