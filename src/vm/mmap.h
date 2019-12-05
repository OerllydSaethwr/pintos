//
// Created by vishwam on 02/12/2019.
//

#ifndef PINTOS_08_MMAP_H
#define PINTOS_08_MMAP_H
#define MAPID_START 2

#include <hash.h>
#include <userprog/pagedir.h>
#include "userprog/syscall.h"
#include "filesys/off_t.h"

struct mmap_entry {
  struct hash_elem hash_elem;
  void *location_of_file;
  mapid_t map_id;
  struct file *file;
  uint32_t size;
};

typedef struct hash_elem *mmapid_t;

mmapid_t mmap_file(int fd, void *addr);
mmapid_t mmap_segment(struct file *file, off_t segment_offset, uint32_t read_bytes, void *upage_start);

void mmap_unmap(mmapid_t mapid);
void mmap_unmap_hash(mmapid_t mapid);

#endif //PINTOS_08_MMAP_H
