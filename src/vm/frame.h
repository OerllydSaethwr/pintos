//
// Created by dmv18 on 27/11/2019.
//

#ifndef PINTOS_08_FRAME_H
#define PINTOS_08_FRAME_H

#include <hash.h>

/* Frame table entry */
struct frame {
  uint32_t frame_no;
  struct thread *process;
  struct hash_elem hash_elem;
};

/* Initialize frame table */
void frame_init(void);

#endif //PINTOS_08_FRAME_H
