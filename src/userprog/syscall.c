#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <threads/synch.h>
#include <filesys/file.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"
#include "process.h"
#define INVALID_OPEN -1

static void syscall_handler (struct intr_frame *);

static int halt(void **);
static int exit(void **);
static int exec(void **);
static int wait(void **);
static int create(void **);
static int remove(void **);
static int open(void **);
static int filesize(void **);
static int read(void **);
static int write(void **);
static int seek(void **);
static unsigned tell(void **);
static int close(void **);

static bool valid_pointer(void *);
static void kill(void);
static void check_pointer(void *pointer);

struct lock filesystem_lock;

/* Array of function pointers the handler delegates to. */
static int (*fpa[13]) (void **argv) = {
    halt, exit, exec, wait, create, remove, open, filesize, read, write, seek, tell, close
};

/* Argument counts of handler function. */
static int argument_counts[] = {ARG_NUM_HALT, ARG_NUM_EXIT, ARG_NUM_EXEC, ARG_NUM_WAIT, ARG_NUM_CREATE, ARG_NUM_REMOVE, ARG_NUM_OPEN, ARG_NUM_FILESIZE, ARG_NUM_READ, ARG_NUM_WRITE, ARG_NUM_SEEK, ARG_NUM_TELL, ARG_NUM_CLOSE};

/* Lock filesystem access. Using common lock */
static void filesystem_access_lock() {
  lock_acquire(&filesystem_lock);
}

/* Unlock filesystem access. Using common lock */
static void filesystem_access_unlock() {
  lock_release(&filesystem_lock);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f )
{
  int *sp = f->esp;
  check_pointer(sp);

  /* Creating argument array */
  int argc = argument_counts[*sp];
  void *argv[argc + 1];
  for (int i = 0; i < argc; i++) {
    argv[i] = sp + i + 1;
  }
  argv[argc] = &f->eax;

  /* Checking if pointers are valid */
  for (int i = 0; i < argc; ++i) {
    check_pointer(argv[i]);
  }

  /* Delegating to handler */
  f->eax = fpa[*sp](argv);
}

/* void halt(void); */
static int halt(void **_ UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

/* int exit(int status); */
static int exit(void **argv) {
  int status = *(int *) argv[0];
  int *eax = (int *) argv[1];
  *eax = status;
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

/* pid_t exec(const char *cmd_line); */
static int exec(void **argv) {
  char *cmd_line = *(char **) argv[0];
  return process_execute(cmd_line);
}

/* int wait(pid_t pid); */
static int wait(void **argv) {
  tid_t child_tid = *(tid_t *) argv[0];
  return process_wait(child_tid);
}

/* bool create(const char *file, unsigned initial_size); */
static int create(void **argv) {
    return filesys_create(argv[0], *(unsigned *) argv[1]);
}

/* bool remove(const char *file); */
static int remove(void **argv) {
    return filesys_remove(argv[0]);
}

/* int open(const char *file); */
static int open(void **argv) {
    struct file *opened_file = filesys_open(argv[0]);

    if (opened_file != NULL) {
        struct file_descriptor new;
        new.descriptor = ++thread_current()->curr_file_descriptor;
        new.file = opened_file;

        list_push_back(&thread_current()->file_descriptors, &new.thread_elem);

        return new.descriptor;
    }

    return INVALID_OPEN;
}

/* int filesize(int fd); */
static int filesize(void **argv) {
  int fd = (int) &argv[0];
  /* -1 if file can not be opened*/
  int size_of_file = -1;

  filesystem_access_lock();

  /* Go through the list and see if this file descriptor exists. */
  struct file *file = file_finder(fd);
  if (file != NULL) {
      size_of_file = file_length(file);
  }

  filesystem_access_unlock();

  return size_of_file;
}

/* int read(int fd, void *buffer, unsigned size); */
static int read(void **argv) {
  int fd = (int) &argv[0];
  void *buffer = &argv[1];
  unsigned size = (unsigned) &argv[2];
  int read_bytes = -1;


  if (fd == STDIN_FILENO) {
    char *input_buffer = (char *) buffer;
    for (int pos = 0; pos < size; pos++) {
      input_buffer[pos] = input_getc();
    }
    read_bytes = size;

  } else {
    filesystem_access_lock();
    struct file *file = file_finder (fd);
    if (file != NULL) {
      read_bytes = file_read (file, buffer, size);
    }
    filesystem_access_unlock();
  }

  return read_bytes;
}


/* int write(int fd, void *buffer, unsigned size); */
static int write(void **argv) {
  int fd = *(int *) argv[0];
  const char *buffer = *(const char **) argv[1];
  unsigned size = *(unsigned *) argv[2];

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
  } else {
    //FIXME
    //file_write(fd, buffer, size);
  }

  return size;
}

/* void seek(int fd, unsigend position); */
static int seek(void **argv) {
  int fd = (int) &argv[0];
  unsigned  position = (unsigned) &argv[1];
  filesystem_access_lock();
  struct file *file = file_finder(fd);
  file_seek(file, position);
  filesystem_access_unlock();
//TODO fix return value
}

/* unsigned tell(int fd); */

static unsigned tell(void **argv) {
  int fd = (int) &argv[0];
  filesystem_access_lock();
  struct file *file = file_finder(fd);
  unsigned new_position = -1;
  if (file != NULL) {
    new_position = file_tell(file);
  }
  filesystem_access_unlock();
  return  new_position;
}

/* void close(int fd); */
static int close(void **argv) {
  int fd = (int) &argv[0];
  filesystem_access_lock ();
  struct file *file = file_finder(fd);
  if (file != NULL) {
    file_close (file);
  }
  filesystem_access_unlock ();
  return 0;
}

static void check_pointer(void *pointer) {
  if (!valid_pointer(pointer))
    kill();
}

static bool valid_pointer(void *pointer) {
  return pointer != NULL
                    && is_user_vaddr(pointer)
                    && pagedir_get_page(thread_current()->pagedir, pointer);
}

static void kill(void) {
  struct thread *t = thread_current();
  t->exit_status = STATUS_KILLED;
  printf("%s: exit(%d)\n", t->name, t->exit_status);
  thread_exit();
}

struct file *file_finder (int fd) {
  struct list_elem *elem;
  for (elem = list_begin (&thread_current()->file_descriptors);
       elem != list_end (&thread_current()->file_descriptors);
       elem = list_next (elem)) {
    /* Return a pointer to file matching file descriptor. */
    if (list_entry(elem, struct file_descriptor, thread_elem)->descriptor == fd)
      return list_entry(elem, struct file_descriptor, thread_elem)->file;
  }
  return NULL;
}
