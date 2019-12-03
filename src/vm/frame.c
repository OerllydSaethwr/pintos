#include <kernel/hash.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "frame.h"
#include "debug.h"

static unsigned frame_hash(const struct hash_elem *, void *);
static bool frame_less_func(const struct hash_elem *,
                            const struct hash_elem *,
                            void *);
static uint32_t FRAME_NUM = 0;

struct hash frame_table;
struct lock frame_lock;
void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_less_func, NULL);
  lock_init(&frame_lock);
}

static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct frame *f = hash_entry(e, struct frame, hash_elem);
  return f->frame_no;
}

static bool frame_less_func(const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED) {
  struct frame *frame_a = hash_entry(a, struct frame, hash_elem);
  struct frame *frame_b = hash_entry(b, struct frame, hash_elem);
  return frame_a->frame_no < frame_b->frame_no;
}

/* Get a frame of memory for the current thread */
void* falloc_get_frame(void *upage, PALLOC_FLAGS flag)
{
  ASSERT(is_user_vaddr(upage));
  void *kpage = palloc_get_page(PAL_USER | flag);

  lock_acquire(&frame_lock);

  if (kpage == NULL) {
    /* Evict to make space*/
//    evict_frame();
    kpage = palloc_get_page(flag);
    ASSERT(kpage != NULL);
  }
  struct frame *new = (struct frame *) malloc(sizeof(struct frame));

  if (new == NULL) {
    PANIC("Cannot allocated a new frame");
  }

  new->process = thread_current();
  new->kaddr = kpage;
  new->uaddr = upage;
  new->frame_no = ++FRAME_NUM;
  struct hash_elem *success = hash_insert(&frame_table, &new->hash_elem);
  lock_release (&frame_lock);

  if (success != NULL) {
    PANIC("Tried to insert already exisiting frame into table");
  }

  return kpage;
}