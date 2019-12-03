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

static struct lock mmap_id_lock;

void mmap_table_init(void) {
  hash_init(&mmap_table, mmap_hash, mmap_less_func, NULL);
  lock_init(&mmap_id_lock);
}

mapid_t allocate_map_id(void) {
  static mapid_t next_id = 2;
  lock_acquire(&mmap_id_lock);
  mapid_t map_id;
  map_id = next_id++;
  if (next_id == 0) {
    next_id = 2;
    map_id = next_id++;
  }
  lock_release(&mmap_id_lock);
  return map_id;
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
  hash_destroy(&mmap_table, delete_and_free);
}

void m_unmap(mapid_t map_id) {
  struct mmap_entry temp;
  temp.map_id = map_id;
  struct hash_elem* actual_hash = hash_find(&mmap_table, &temp.hash_elem);

  if (actual_hash) {
    struct mmap_entry* me = hash_entry(actual_hash, struct mmap_entry, hash_elem);
    off_t curr_offset = 0;

    //printf("hash id : %d\n", me->map_id);

    while (curr_offset < me->size) {
      uint32_t read_bytes = ((me->size - curr_offset) > PGSIZE) ? PGSIZE : (me->size - curr_offset);

      //printf("size : %u\n", me->size);
      //printf("me location of file: %p\n", (me->location_of_file));

      void *addr = (void *) pagedir_get_page(thread_current()->pagedir, (void *) ( (uint32_t) me->location_of_file + curr_offset));
      //printf("addr %p\n", addr);
      if (addr != NULL && pagedir_is_dirty(thread_current()->pagedir, (void *) ((uint32_t) me->location_of_file+ curr_offset))) {
        /*char buffer[read_bytes];
        int curr_byte = 0;

        while (curr_byte <= read_bytes) {
          buffer[curr_byte] = *(char *) ((void *) ((uint32_t) me->location_of_file + curr_offset + curr_byte));
          curr_byte++;
        }*/
        file_seek(me->file, curr_offset);
        file_write(me->file, (void *) ((uint32_t) me->location_of_file + curr_offset), read_bytes);
      }

      curr_offset += PGSIZE;
    }
    file_close(me->file);
    hash_delete(&mmap_table, &me->hash_elem);
    free(me);
  }

}