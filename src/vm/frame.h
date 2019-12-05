#ifndef PINTOS_08_FRAME_H
#define PINTOS_08_FRAME_H

#include <hash.h>
#include "threads/palloc.h"
#include "utils.h"

/* Frame table entry */


struct frame {
  struct thread *process;
  struct hash_elem hash_elem;
  void *kaddr;  /* Address in kernal */
  struct supp_entry *supp;
};

/* Initialize frame table */
void frame_init(void);
void *falloc_get_frame(void *upage);
void falloc_free_frame(void *kpage);
struct frame *frame_to_evict(void);
void print_hash_entries(struct hash_elem *e, void *aux);
#endif
