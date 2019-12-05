#include <kernel/hash.h>
#include <kernel/list.h>
#include <stdio.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "frame.h"
#include "swap.h"
#include "debug.h"

static unsigned frame_hash(const struct hash_elem *, void *);
static bool frame_less_func(const struct hash_elem *,
                            const struct hash_elem *,
                            void *);

struct hash frame_table;
struct lock frame_lock;
struct list circular;
void *oldest_entry;
struct frame *frame_to_evict(void) {
  struct frame *frame = oldest_entry;
  struct list_elem *curr = &frame->list_elem;

  while (true) {
    barrier();

    if (!pagedir_is_accessed(frame->process->pagedir, frame->supp->upage)) {
      if (curr->next == &circular.tail) {
        oldest_entry = list_entry(list_begin(&circular),
                                                struct frame, list_elem);
      } else {
        oldest_entry = list_entry(list_next(curr), struct frame,
                                                list_elem);
      }
      return frame;

    } else {
      pagedir_set_accessed(frame->process->pagedir, frame->supp->upage, 0);
    }

    curr = curr->next;
    if (curr == &circular.tail) {
      frame = list_entry(list_front(&circular), struct frame, list_elem);
      curr = list_front(&circular);
    } else {
      frame = list_entry(curr, struct frame, list_elem);
    }
  }
}

void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_less_func, NULL);
  lock_init(&frame_lock);
  list_init(&circular);
}

static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct frame *f = hash_entry(e, struct frame, hash_elem);
  return (unsigned) f->kaddr;
}

static bool frame_less_func(const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED) {
  struct frame *frame_a = hash_entry(a, struct frame, hash_elem);
  struct frame *frame_b = hash_entry(b, struct frame, hash_elem);
  return frame_a->kaddr < frame_b->kaddr;
}

/* Get a frame of memory for the current thread.
 * Only used to manage USER pages.
 * It's the caller's responsibility to allocate and use
 * supp_entry correctly. */
struct frame *falloc_get_frame(void *upage)
{
  ASSERT(is_user_vaddr(upage));
  lock_acquire(&frame_lock);
  void *kpage = palloc_get_page(PAL_USER);

  retry:
  if (kpage == NULL) {
    lock_release(&frame_lock);
    /* Evict to make space*/
    evict_frame(frame_to_evict());
    lock_acquire(&frame_lock);
    kpage = palloc_get_page(PAL_USER);
    goto retry;
  }

  struct frame *new = malloc(sizeof(struct frame));

  if (new == NULL) {
    PANIC("Out of kernel memory.\n");
  }

  list_push_front(&circular, &(new->list_elem));
  if (list_size(&circular) == 1) {
    oldest_entry = new;
  }

  new->process = thread_current();
  new->kaddr = kpage;
  struct hash_elem *success = hash_insert(&frame_table, &new->hash_elem);
  lock_release (&frame_lock);

  if (success != NULL) {
    PANIC("Attempting to insert already existing entry into frame table.\n");
  }

  return new;
}

void falloc_free_frame(void *kpage) {
  ASSERT(is_kernel_vaddr(kpage));
  struct frame temp;

  temp.kaddr = kpage;
  lock_acquire(&frame_lock);

  struct hash_elem *e = hash_find(&frame_table, &temp.hash_elem);
  if (!e) {
    return;
  }

  ASSERT(temp.kaddr == hash_entry(e, struct frame, hash_elem)->kaddr);
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  if (oldest_entry == frame) {
    if (list_next(&frame->list_elem) == NULL) {
      oldest_entry = list_entry(list_front(&circular),
                                              struct frame,
                                              list_elem);
    } else {
      oldest_entry = list_entry(list_next(&frame->list_elem),
                                              struct frame, list_elem);
    }
  }
  list_remove(&frame->list_elem);

  palloc_free_page(frame->kaddr);
  hash_delete(&frame_table, e);
  free(frame);
  lock_release(&frame_lock);

}

void print_hash_entries(struct hash_elem *e, void *aux UNUSED) {
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  printf("Frame has kaddr %p\n", frame->kaddr);
}

