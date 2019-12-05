#ifndef PINTOS_08_FRAME_H
#define PINTOS_08_FRAME_H

#include <hash.h>
#include "threads/palloc.h"
#include "utils.h"

/* Frame table entry */


struct frame {
  struct thread *process;
  struct hash_elem hash_elem;
  struct file *file;
  void *kaddr;  /* Address in kernal */
  void *uaddr;  /* Address in user space */
  enum page_type page_type;
  struct mmap_entry * m_entry;
};

/* Initialize frame table */
void frame_init(void);
void *falloc_get_frame(void *upage, PALLOC_FLAGS flag, page_type type,
                       struct file *file);
void falloc_free_frame(void *kpage);
void print_hash_entries(struct hash_elem *e, void *aux);
#endif
