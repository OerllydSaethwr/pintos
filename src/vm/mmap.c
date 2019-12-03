//
// Created by vishwam on 02/12/2019.
//

#include <filesys/file.h>
#include <threads/thread.h>
#include "threads/synch.h"
#include "mmap.h"
#include "threads/malloc.h"
#include <stdio.h>

static unsigned mmap_hash(const struct hash_elem *, void *);
static bool mmap_less_func(const struct hash_elem *,
                            const struct hash_elem *,
                            void *);


void mmap_table_init(struct hash *hash_map) {
  hash_init(hash_map, mmap_hash, mmap_less_func, NULL);
}

mapid_t allocate_map_id(void) {
  return thread_current()->mmap_id++;
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

void m_unmap(mapid_t map_id) {
  struct mmap_entry temp;
  temp.map_id = map_id;
  struct hash_elem* actual_hash = hash_find(&thread_current()->mmap_table, &temp.hash_elem);

  if (actual_hash) {
    unmap_hash(actual_hash, NULL);
  }

}

void unmap_hash (struct hash_elem *e, void *aux UNUSED) {
  struct mmap_entry *me = hash_entry(e, struct mmap_entry, hash_elem);

  off_t curr_offset = 0;

  while (curr_offset < me->size) {
    uint32_t read_bytes = ((me->size - curr_offset) > PGSIZE) ? PGSIZE : (
        me->size - curr_offset);

    void *curr_loc = (void *) ((uint32_t) me->location_of_file + curr_offset);
    void *addr = (void *) pagedir_get_page(thread_current()->pagedir,
                                           curr_loc);

    if (addr != NULL &&
        pagedir_is_dirty(thread_current()->pagedir, curr_loc)) {
      file_seek(me->file, curr_offset);
      file_write(me->file, curr_loc, read_bytes);
    }

    pagedir_clear_page(thread_current()->pagedir, curr_loc);

    curr_offset += PGSIZE;
  }

  file_close(me->file);
  hash_delete(&thread_current()->mmap_table, &me->hash_elem);
  free(me);
}