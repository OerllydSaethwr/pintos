//
// Created by Raghav Khanna on 1/12/19.
//

#include "utils.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
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

struct addr_info*
create_and_insert_spt_page(uint32_t initial_page, struct file *file,
                           off_t segment_offset, uint32_t read_bytes,
                           bool writeable, curr_location location,
                           page_type type, uint32_t uaddr, uint32_t kaddr) {
  struct addr_info *addr_info = malloc(sizeof(struct addr_info));
  addr_info->initial_page = initial_page;
  addr_info->file = file;
  addr_info->segment_offset = segment_offset;
  addr_info->read_bytes = read_bytes;
  addr_info->writeable = writeable;
  addr_info->location = location;
  addr_info->type = type;
  addr_info->uaddr = uaddr;
  addr_info->kaddr = kaddr;
  hash_insert(&thread_current()->supp_table, &addr_info->hash_elem);
  return addr_info;
}



  bool is_stack_access(const void *ptr, void *esp)
{

  //printf("Verifying\n");
  /* Valid pointer if it's above  esp or 4 below (PUSH) or 32 below (PUSHA) */
  return (ptr >= (const void *) PHYS_BASE - MAX_STACK_SIZE && ptr < PHYS_BASE)
         && (ptr >= esp || ptr == esp - 4 || ptr == esp - 32);
}


void print_addr_info(struct addr_info *ai) {
  if (ai) {


    printf("_________________________________________________________________\n"
           "initial_page = %x\n"
           "file = %p\n"
           "segment_offset = %d\n"
           "read_bytes = %d\n"
           "writeable = %d\n"
           "location = %d\n"
           "type = %d;\n"
           "uaddr = %x\n"
           "kaddr = %x\n"
           "_________________________________________________________________\n"
           ,ai->initial_page, ai->file, ai->segment_offset,
           ai->read_bytes, ai->writeable, ai->location, ai->type, ai->uaddr,
           ai->kaddr);
  } else {
    printf("null");
  }
}