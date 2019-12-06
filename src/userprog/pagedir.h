#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H

#include <stdbool.h>
#include <stdint.h>
#include "threads/pte.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "syscall.h"
#include "vm/mmap.h"
#include "vm/utils.h"
#include <hash.h>

typedef struct hash_elem *mmapid_t;

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
  LOADED
};

enum page_type {
  STACK,
  MMAP,
  EXEC_CODE,
  EXEC_DATA
};

struct supp_entry {
  void *upage;
  struct file *file;
  off_t offset;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writeable;
  enum location location;
  enum page_type ptype;
  mmapid_t mapping;
  bool dirty;
  struct semaphore eviction_sema;
};


#endif /* userprog/pagedir.h */
