#ifndef PINTOS_08_FRAME_H
#define PINTOS_08_FRAME_H

#include <hash.h>
#include "threads/palloc.h"
/* Frame table entry */
struct frame {
  uint32_t frame_no;
  struct thread *process;
  struct hash_elem hash_elem;

  void *kaddr;  /* Address in kernal */
  void *uaddr;  /* Address in user space */
};

/* Initialize frame table */
void frame_init(void);
void *get_frame_for_page(void *upage, PALLOC_FLAGS);
static  uint32_t FRAME_NUM = 0;
#endif //PINTOS_08_FRAME_H
