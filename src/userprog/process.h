
#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/off_t.h"
#include "threads/thread.h"
#include "pagedir.h"

#define INVALID_WAIT -1
#define MAX_STRING_LENGTH 256

struct start_proc_aux {
    struct semaphore load_finish;
    char *file_name;
    bool success;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool lazy_load_page(struct file *file,off_t ofs, uint8_t *upage, bool writable, struct supp_entry *);

#endif /* userprog/process.h */

