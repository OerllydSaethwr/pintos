#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H

#include <stdbool.h>
#include <stdint.h>
#include <vm/utils.h>
#include <vm/mmap.h>
#include "threads/pte.h"
#include "filesys/off_t.h"
#include "syscall.h"

uint32_t *pagedir_create (void);
void pagedir_destroy (uint32_t *pd);
bool pagedir_set_page (uint32_t *pd, void *upage, void *kpage, bool rw, enum pte_type);
void *pagedir_get_page (uint32_t *pd, const void *upage);
void pagedir_clear_page (uint32_t *pd, void *upage);
bool pagedir_is_dirty (uint32_t *pd, const void *upage);
void pagedir_set_dirty (uint32_t *pd, const void *upage, bool dirty);
bool pagedir_is_accessed (uint32_t *pd, const void *upage);
void pagedir_set_accessed (uint32_t *pd, const void *upage, bool accessed);
void pagedir_activate (uint32_t *pd);
bool pagedir_is_writeable(uint32_t *pd, const void *upage);

struct supp_entry *pagedir_get_fake(uint32_t *pd, const void *uaddr);

enum location {
  SWAP,
  FSYS,
  SHARED
};

struct supp_entry {
  uint32_t initial_page;
  struct file *file;
  off_t segment_offset;
  uint32_t read_bytes;
  struct mmap_entry *map_entry;
  bool writeable;
  enum location location;
  page_type type;
};


#endif /* userprog/pagedir.h */
