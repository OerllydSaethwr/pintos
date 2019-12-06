#include <kernel/hash.h>
#include <kernel/list.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "userprog/process.h"
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
struct lock frame_table_lock;
struct lock circular_list_lock;
struct semaphore eviction_sema;

struct list circular;
void *oldest_entry;
struct frame *frame_to_evict(void) {
//  return frame_to_evict_safe();
  lock_acquire(&circular_list_lock);
  struct list_elem *e = list_pop_front(&circular);
  struct frame *curr = list_entry(list_pop_front(&circular), struct frame, list_elem);

  //return curr;
  while (true) {
    if (!pagedir_is_accessed(curr->process->pagedir, curr->supp->upage) && !curr->supp->pinned) {
      lock_release(&circular_list_lock);
      return curr;
    } else {
      pagedir_set_accessed(curr->process->pagedir, curr->supp->upage, 0);
    }
    list_push_back(&circular, e);
    e = list_pop_front(&circular);
    curr = list_entry(e, struct frame, list_elem);
  }

}

struct frame *frame_to_evict_safe(void) {
  static uint32_t cnt = 0;
  static const void *start = (void *) 0xc0271000;
  struct frame temp;
  retry:
  temp.kaddr = (void *) start + ((cnt++) * PGSIZE);
  struct hash_elem *elem = hash_find (&frame_table, &temp.hash_elem);
  if (!elem) {
    cnt = 0;
    goto retry;
  }
  return hash_entry (elem, struct frame, hash_elem);
}


void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_less_func, NULL);
  lock_init(&frame_table_lock);
  lock_init(&circular_list_lock);
  list_init(&circular);
  sema_init(&eviction_sema, 1);
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
  sema_down(&eviction_sema);
  void *kpage = palloc_get_page(PAL_USER);
  sema_up(&eviction_sema);

  while (kpage == NULL) {
    /* Evict to make space*/
    sema_down(&eviction_sema);
    evict_frame();
    kpage = palloc_get_page(PAL_USER);
    sema_up(&eviction_sema);
  }

  lock_acquire(&frame_table_lock);
  struct frame *new = malloc(sizeof(struct frame));

  if (new == NULL) {
    PANIC("Out of kernel memory.\n");
  }
  lock_acquire(&circular_list_lock);

//  list_push_front(&circular, &(new->list_elem));
//  if (list_size(&circular) == 1) {
//    oldest_entry = new;
//  }

  pagedir_set_accessed(thread_current()->pagedir, upage, 0);


  list_push_back(&circular, &(new->list_elem));
  lock_release(&circular_list_lock);

  new->process = thread_current();
  new->kaddr = kpage;
  struct hash_elem *success = hash_insert(&frame_table, &new->hash_elem);
  lock_release (&frame_table_lock);

  if (success != NULL) {
    PANIC("Attempting to insert already existing entry into frame table.\n");
  }

  return new;
}

void falloc_free_frame(void *kpage) {
  ASSERT(is_kernel_vaddr(kpage));
  struct frame temp;

  temp.kaddr = kpage;
  lock_acquire(&frame_table_lock);

  struct hash_elem *e = hash_find(&frame_table, &temp.hash_elem);
  if (!e) {
    return;
  }

  ASSERT(temp.kaddr == hash_entry(e, struct frame, hash_elem)->kaddr);
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  lock_acquire(&circular_list_lock);
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
  lock_release (&circular_list_lock);
  palloc_free_page(frame->kaddr);
  hash_delete(&frame_table, e);
  free(frame);
  lock_release(&frame_table_lock);
}

void print_hash_entries(struct hash_elem *e, void *aux UNUSED) {
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  printf("Frame has kaddr %p\n", frame->kaddr);
}

void allocate_stack_page(void *upage) {
  struct supp_entry *supp = malloc(sizeof(struct supp_entry));
  if (!supp)
    PANIC("Failed to allocate memory for supp entry for stack frame.\n");
  supp->location = LOADED;
  supp->writeable = true;
  supp->ptype = STACK;
  supp->upage = upage;
  supp->read_bytes = PGSIZE;
  sema_init(&supp->eviction_sema, 0);

  struct frame *frame = falloc_get_frame(upage);
  frame->supp = supp;
  install_page (upage, frame->kaddr, supp->writeable);
}

