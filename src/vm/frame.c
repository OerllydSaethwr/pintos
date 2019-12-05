#include <kernel/hash.h>
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

static void set_accessed_bits_to_0(void);

struct hash frame_table;
struct lock frame_lock;

struct frame *frame_to_evict(void) {
  struct frame *frame = eviction_list.oldest_entry;
  struct list_elem curr = frame->list_elem;

  while (true) {
    if (!pagedir_is_accessed(thread_current()->pagedir, frame->supp->upage)) {
      if (list_next(&curr) == NULL) {
        eviction_list.oldest_entry = list_entry(list_front(&eviction_list.circular), struct frame, list_elem);
      } else {
        eviction_list.oldest_entry = list_entry(list_next(&curr), struct frame, list_elem);
      }
      return frame;

    } else {
      pagedir_set_accessed(thread_current()->pagedir, frame->supp->upage, 0);
    }

    curr = *list_next(&curr);
    frame = list_entry(list_next(&curr), struct frame, list_elem);
  }
}

void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_less_func, NULL);
  lock_init(&frame_lock);
  list_init(&eviction_list.circular);
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
 * Only used to manage USER pages. */
void *falloc_get_frame(void *upage)
{
  ASSERT(is_user_vaddr(upage));
  void *kpage = palloc_get_page(PAL_USER);
  lock_acquire(&frame_lock);

  static int frames_allocated = 0;

  if (kpage == NULL) {
    /* Evict to make space*/
    struct frame *chosen = frame_to_evict();
    struct thread *thread = chosen->process;
    struct supp_entry *placement = swap_to_swap(chosen);
    pagedir_set_page (thread->pagedir, upage, placement,
                      placement->writeable, FAKE);
    kpage = palloc_get_page(PAL_USER);
    ASSERT(kpage != NULL);
  }

  struct frame *new = (struct frame *) malloc(sizeof(struct frame));

  ++frames_allocated;

//  if (frames_allocated == RESET_ACCESS_BITS) {
//    frames_allocated = 0;
//    set_accessed_bits_to_0();
//  }

  if (new == NULL) {
    PANIC("Out of kernel memory.\n");
  }
//  barrier();
//  printf("here\n");
  list_push_back(&eviction_list.circular, &new->list_elem);
//  if (list_size(&eviction_list.circular) == 1) {
//    eviction_list.oldest_entry = &new;
//  }

  new->process = thread_current();
  new->kaddr = kpage;
  struct hash_elem *success = hash_insert(&frame_table, &new->hash_elem);
  lock_release (&frame_lock);

  if (success != NULL) {
    PANIC("Attempting to insert already existing entry into frame table.\n");
  }

  return kpage;
}

void falloc_free_frame(void *kpage) {
  ASSERT(is_kernel_vaddr(kpage));
  struct frame temp;

  temp.kaddr = kpage;

  struct hash_elem *e = hash_find(&frame_table, &temp.hash_elem);
  if (!e) {
    return;
  }

  hash_delete(&frame_table, e);

  ASSERT(temp.kaddr == hash_entry(e, struct frame, hash_elem)->kaddr);
  ASSERT(!hash_find(&frame_table, e));
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  palloc_free_page(frame->kaddr);
  free(frame);
}

void print_hash_entries(struct hash_elem *e, void *aux UNUSED) {
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  printf("Frame has kaddr %p\n", frame->kaddr);
}

static void set_accessed_bits_to_0(void) {
  struct list_elem *e;
  for (e = list_begin (&eviction_list.circular); e != list_end (&eviction_list.circular); e = list_next (e))
  {
    struct frame *f = list_entry (e, struct frame, list_elem);
    pagedir_set_accessed(thread_current()->pagedir,f->supp->upage,0);
  }
}



