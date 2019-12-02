//
// Created by vishwam on 02/12/2019.
//

#include <filesys/file.h>
#include "mmap.h"
#include "threads/malloc.h"

static unsigned mmap_hash(const struct hash_elem *, void *);
static bool mmap_less_func(const struct hash_elem *,
                            const struct hash_elem *,
                            void *);


void mmap_table_init(void) {
  mmap_table = malloc(sizeof(mmap_table));
  hash_init(&mmap_table->mmap_table, mmap_hash, mmap_less_func, NULL);
  mmap_table->map_id = 1;
}

static unsigned mmap_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct mmap_entry* me = hash_entry(e, struct mmap_entry, hash_elem);
  return me->map_id;
}

static bool mmap_less_func(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED) {
  struct mmap_entry* me_a = hash_entry(a, struct mmap_entry, hash_elem);
  struct mmap_entry* me_b = hash_entry(b, struct mmap_entry, hash_elem);

  return me_a->map_id < me_b->map_id;
}

static void delete_and_free (struct hash_elem *e, void *aux UNUSED) {
  struct mmap_entry *me = hash_entry (e, struct mmap_entry, hash_elem);
  free (me);
}

void mmap_table_free(void) {
  hash_destroy(&mmap_table->mmap_table, delete_and_free);
  free(mmap_table);
}