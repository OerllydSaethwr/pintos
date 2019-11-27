//
// Created by dmv18 on 27/11/2019.
//

#include <kernel/hash.h>
#include "frame.h"
#include "debug.h"

static unsigned frame_hash(const struct hash_elem *, void *);
static bool frame_less_func(const struct hash_elem *,
                            const struct hash_elem *,
                            void *);

struct hash frame_table;

void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_less_func, NULL);
}

static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct frame *f = hash_entry(e, struct frame, hash_elem);
  return hash_int(f->frame_no);
}

static bool frame_less_func(const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED) {
  struct frame *frame_a = hash_entry(a, struct frame, hash_elem);
  struct frame *frame_b = hash_entry(b, struct frame, hash_elem);
  return frame_a->frame_no < frame_b->frame_no;
}

