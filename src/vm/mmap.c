//
// Created by vishwam on 02/12/2019.
//

#include <filesys/file.h>
#include <threads/thread.h>
#include "threads/synch.h"
#include "mmap.h"
#include "threads/malloc.h"
#include "frame.h"
#include <stdio.h>
#include "userprog/process.h"

static mapid_t allocate_map_id(void);
static bool overlapping_mapped_mem(uint32_t file_size, void *upage);

static mapid_t allocate_map_id(void) {
  if(thread_current()->mmap_id == 0) {
    thread_current()->mmap_id = MAPID_START;
  }
  return thread_current()->mmap_id++;
}

mmapid_t mmap_file(int fd, void *addr) {
  struct file_descriptor *file_desc = file_descriptor_finder(fd);

  if (!file_desc) {
    return INVALID;
  }

  return mmap_segment(file_desc->actual_file, 0, file_length(file_desc->actual_file), addr);
}

mmapid_t mmap_segment(struct file *file, off_t segment_offset, uint32_t read_bytes, void *upage_start) {
  if (upage_start == NULL || !file || !file_length(file) || !read_bytes || (uint32_t) upage_start % PGSIZE != 0
            || overlapping_mapped_mem(file_length(file), upage_start))
    return INVALID;

  struct file *mmap_instance = file_reopen(file);
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));

  if (!fd) {
    PANIC("Failed to allocate memory for file descriptor.\n");
  }

  fd->actual_file = mmap_instance;
  fd->descriptor = ++(thread_current ()->curr_file_descriptor);
  fd->upage = upage_start;
  hash_insert (&thread_current ()->file_hash_descriptors,
               &fd->thread_hash_elem);

  bool page_aligned = read_bytes % PGSIZE == 0;
  create_fake_multiple(upage_start, mmap_instance, read_bytes, page_aligned ? 0 : PGSIZE - (read_bytes % PGSIZE), segment_offset, MMAP, true, &fd->thread_hash_elem);

  return &fd->thread_hash_elem;
}

void unmap_file_with_remove_hash(mmapid_t mapid) {
  unmap_file(mapid);
  hash_delete(&thread_current()->file_hash_descriptors, mapid);
}

void unmap_file(mmapid_t map_id) {
  off_t curr_offset = 0;

  struct file_descriptor *fd = hash_entry(map_id, struct file_descriptor, thread_hash_elem);
  struct file *file = fd->actual_file;

  uint32_t size = file_length(file);

  while (curr_offset < size) {
    uint32_t read_bytes = (size - curr_offset) > PGSIZE ? PGSIZE : (size - curr_offset);

    void *curr_loc = (void *) ((uint32_t) fd->upage + curr_offset);
    void *addr = pagedir_get_page(thread_current()->pagedir,
                                           curr_loc);
    if (addr != NULL &&
        pagedir_is_dirty(thread_current()->pagedir, curr_loc)) {
//      lock_the_filesys();
      file_seek(file, curr_offset);
      file_write(file, curr_loc, read_bytes);
//      unlock_the_filesys();
    }

    if (addr != NULL) {
      falloc_free_frame (addr);
    }

    pagedir_clear_page(thread_current()->pagedir, curr_loc);
    curr_offset += PGSIZE;
  }

  file_close(file);
}

static bool overlapping_mapped_mem(uint32_t file_size, void *upage) {
  uint32_t curr_bytes = 0;
  while (file_size > curr_bytes) {
    uint32_t new_address = (uint32_t) upage + curr_bytes;
    void *get_page = pagedir_get_page(thread_current()->pagedir, (void *) (new_address));
    void *get_fake = pagedir_get_fake(thread_current()->pagedir, (void *) new_address);

    if (is_user_vaddr(upage) && (get_page != NULL || get_fake != NULL)) {
      return true;
    }

    curr_bytes += PGSIZE;
  }
  return false;
}