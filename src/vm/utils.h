//
// Created by Raghav Khanna on 1/12/19.
//

#include "lib/kernel/hash.h"
#include "filesys/off_t.h"
#include "lib/stdbool.h"

#ifndef UTILS
#define UTILS
#define MAX_STACK_SIZE 10485760  /* 10 MiB hard maximum for stack*/
#define USE_SUPP_TABLE 1

#define NULL_INT 0

bool is_stack_access(const void *ptr, void *esp);

void supp_table_init(struct hash *hash_map);


typedef enum page_type {
  STACK,
  MMAP,
  EXEC_CODE,
  EXEC_DATA
} page_type;


typedef enum curr_location {
  IN_SWAP,
  IN_FSYS,
  IN_MEM
} curr_location;

struct addr_info {
  uint32_t initial_page;
  struct file *file;
  off_t segment_offset;
  uint32_t read_bytes;
  bool writeable;
  curr_location location;
  page_type type;
  struct hash_elem hash_elem;
  uint32_t uaddr;
  uint32_t kaddr;
};


struct addr_info* get_addr_info_entry(uint32_t);

struct addr_info*
create_and_insert_spt_page(uint32_t, struct file *, off_t, uint32_t, bool,
                           curr_location, page_type, uint32_t, uint32_t);
void print_addr_info(struct addr_info*);
#endif