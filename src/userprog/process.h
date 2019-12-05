
#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <vm/utils.h>
#include "filesys/off_t.h"
#include "threads/thread.h"
#include "pagedir.h"

#define INVALID_WAIT -1
#define MAX_STRING_LENGTH 256
#define DEBUG_FREE 0xcccccccc

struct start_proc_aux {
    struct semaphore load_finish;
    char *file_name;
    bool success;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool load_segment_lazy(struct supp_entry *supp_entry);
bool install_page (void *upage, void *kpage, bool writable);

bool create_fake_single(void *upage,
                        enum location location,
                        void *container,
                        off_t offset,
                        uint32_t read_bytes,
                        uint32_t zero_bytes,
                        enum page_type ptype,
                        bool writable,
                        mmapid_t mapping);

bool create_fake_multiple(void *upage_start,
                          struct file *file,
                          uint32_t read_bytes,
                          uint32_t zero_bytes,
                          off_t offset,
                          enum page_type ptype,
                          bool writable,
                          mmapid_t mapping);

#endif /* userprog/process.h */

