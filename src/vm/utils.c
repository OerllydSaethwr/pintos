//
// Created by Raghav Khanna on 1/12/19.
//

#include "utils.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include <stdio.h>
#include "lib/kernel/hash.h"

static unsigned supp_hash(const struct hash_elem *e, void *aux UNUSED);
static bool supp_less_func(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED);

void supp_table_init(struct hash * supp_table) {
  hash_init(supp_table, supp_hash, supp_less_func, NULL);
}


static unsigned supp_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct addr_info* me = hash_entry(e, struct addr_info, hash_elem);
  return me->uaddr;
}

static bool supp_less_func(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED) {
  struct addr_info *me_a = hash_entry(a, struct addr_info, hash_elem);
  struct addr_info *me_b = hash_entry(b, struct addr_info, hash_elem);

  return me_a->uaddr < me_b->uaddr;
}

struct addr_info* get_addr_info_entry(uint32_t uaddr){
  struct addr_info temp;
  temp.uaddr = uaddr;
  struct hash_elem *elem = hash_find(&thread_current()->supp_table, &temp.hash_elem );
  if(elem){
    return hash_entry(elem, struct addr_info, hash_elem);
  }
  return NULL;
}



  bool is_stack_access(const void *ptr, void *esp)
{

  //printf("Verifying\n");
  /* Valid pointer if it's above  esp or 4 below (PUSH) or 32 below (PUSHA) */
  return (ptr >= (const void *) PHYS_BASE - MAX_STACK_SIZE && ptr < PHYS_BASE)
         && (ptr >= esp || ptr == esp - 4 || ptr == esp - 32);
}