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

struct hash frame_table;
struct lock frame_lock;

static struct frame* frame_to_evict(void){
  struct frame temp;
  temp.kaddr = (void *) 0xc0271000;
  struct hash_elem *elem = hash_find (&frame_table, &temp.hash_elem);
  return hash_entry (elem, struct frame, hash_elem);
}

void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_less_func, NULL);
  lock_init(&frame_lock);
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

/* Get a frame of memory for the current thread */
void *falloc_get_frame(void *upage, PALLOC_FLAGS flag, struct addr_info *addr_info)
{

//  printf("getting frame for : %p\n",upage);
  ASSERT(is_user_vaddr(upage));
  void *kpage = palloc_get_page(PAL_USER | flag);
//  printf("kaddr %p\n", kpage);
  lock_acquire(&frame_lock);


  if (kpage == NULL) {
    /* Evict to make space*/
//    struct frame *chosen = frame_to_evict();
//    struct thread *thread = chosen->process;
//    struct supp_entry *placement = evict_frame(chosen);
//    pagedir_set_page (thread->pagedir, upage, placement,
//                      placement->writeable, FAKE);
//    kpage = palloc_get_page(flag);
    ASSERT(kpage != NULL);
  }

  struct frame *new = (struct frame *) malloc(sizeof(struct frame));

  if (new == NULL) {
    PANIC("Cannot allocated a new frame");
  }

  new->process = thread_current();
  new->kaddr = (uint32_t) kpage;
  new->uaddr = addr_info->uaddr;
  new->page_type = addr_info->type;
  new->file = addr_info->file;
  addr_info->kaddr = new->kaddr;
  hash_apply(&frame_table, print_hash_entries);
  struct hash_elem *success = hash_insert(&frame_table, &new->hash_elem);
  lock_release (&frame_lock);

  if (success != NULL) {
    PANIC("Tried to insert already exisiting frame into table");
  }

  return kpage;
}

void falloc_free_frame(void *kpage) {
//  printf("Deleting frame with kaddr %p\n", pagedir_get_page(thread_current()->pagedir, upage));

  ASSERT(is_kernel_vaddr(kpage));
  struct frame temp;

  temp.kaddr = kpage;

//  printf("Deleting frame with kaddr %p\n", temp.kaddr);

  struct hash_elem *e = hash_find(&frame_table, &temp.hash_elem);
  if (!e) {
    return;
  }

  //
//  printf("Deleting frame with kaddr %p\n", temp.kaddr);
  hash_delete(&frame_table, e);

  ASSERT(temp.kaddr == hash_entry(e, struct frame, hash_elem)->kaddr);
  ASSERT(!hash_find(&frame_table, e));
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
  palloc_free_page((void *) frame->kaddr);
  free(frame);
}

void print_hash_entries(struct hash_elem *e, void *aux) {
  struct frame *frame = hash_entry(e, struct frame, hash_elem);
//  printf("Frame has kaddr %p\n", frame->kaddr);
}

