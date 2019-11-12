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
#include "threads/malloc.h"
#include "pagedir.h"
#include "process.h"

#define INVALID_OPEN -1

static void syscall_handler(struct intr_frame *);

static void halt(struct intr_frame *, void **);
static void exit(struct intr_frame *, void **);
static void exec(struct intr_frame *, void **);
static void wait(struct intr_frame *, void **);
static void create(struct intr_frame *, void **);
static void remove(struct intr_frame *, void **);
static void open(struct intr_frame *, void **);
static void filesize(struct intr_frame *, void **);
static void read(struct intr_frame *, void **);
static void write(struct intr_frame *, void **);
static void seek(struct intr_frame *, void **);
static void tell(struct intr_frame *, void **);
static void close(struct intr_frame *, void **);

static bool valid_pointer(void *);
static void check_pointer(void *pointer);

static void filesystem_access_lock(void);
static void filesystem_access_unlock(void);

static struct file_descriptor *file_descriptor_finder (int fd);

struct lock exec_lock;
struct lock filesystem_lock;

/* Array of function pointers the handler delegates to. */
static void (*fpa[13])(struct intr_frame *f, void **argv) = {
    halt, exit, exec, wait, create, remove, open, filesize, read, write, seek,
    tell, close
};

/* Argument counts of handler function. */
static int argument_counts[] = {ARG_NUM_HALT, ARG_NUM_EXIT, ARG_NUM_EXEC,
                                ARG_NUM_WAIT, ARG_NUM_CREATE, ARG_NUM_REMOVE,
                                ARG_NUM_OPEN, ARG_NUM_FILESIZE, ARG_NUM_READ,
                                ARG_NUM_WRITE, ARG_NUM_SEEK, ARG_NUM_TELL,
                                ARG_NUM_CLOSE};

/* Lock filesystem access. Using common lock */
static void filesystem_access_lock() {
  lock_acquire(&filesystem_lock);
}

/* Unlock filesystem access. Using common lock */
static void filesystem_access_unlock() {
  lock_release(&filesystem_lock);
}

void
syscall_init(void) {
  lock_init(&exec_lock);
  lock_init(&filesystem_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) {
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
  fpa[*sp](f, argv);
}

/* void halt(void); */
static void halt(struct intr_frame *__ UNUSED, void **_ UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

/* void exit(int status); */
static void exit(struct intr_frame *_ UNUSED, void **argv) {
  int status = *(int *) argv[0];
  int *eax = (int *) argv[1];
  *eax = status;
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

/* pid_t exec(const char *cmd_line); */
static void exec(struct intr_frame *f, void **argv) {
  check_pointer((void *) *(const char **) argv[0]);
  char *cmd_line = *(char **) argv[0];
  lock_acquire(&exec_lock);
  tid_t pid = process_execute(cmd_line);
  lock_release(&exec_lock);
  f->eax = pid;
}

/* int wait(pid_t pid); */
static void wait(struct intr_frame *f, void **argv) {
  tid_t child_tid = *(tid_t *) argv[0];
  f->eax = process_wait(child_tid);
}

/* bool create(const char *file, unsigned initial_size); */
static void create(struct intr_frame *f, void **argv) {
  check_pointer((void *) *(const char **) argv[0]);
  f->eax = filesys_create(*(const char **) argv[0], *(unsigned *) argv[1]);
}

/* bool remove(const char *file); */
static void remove(struct intr_frame *f, void **argv) {
  check_pointer((void *) *(const char **) argv[0]);
  f->eax = filesys_remove(*(const char **) argv[0]);
}

/* int open(const char *file); */
static void open(struct intr_frame *f, void **argv) {
  check_pointer((void *) *(const char **) argv[0]);
  filesystem_access_lock();
  struct file *opened_file = filesys_open(*(const char **) argv[0]);

  if (opened_file != NULL) {
    struct file_descriptor *new = malloc(sizeof(struct file_descriptor));
    new->descriptor = ++(thread_current()->curr_file_descriptor);
    new->actual_file = opened_file;

    list_push_back(&thread_current()->file_descriptors, &new->thread_elem);
    f->eax = new->descriptor;
  } else {
    f->eax = INVALID_OPEN;
  }

  filesystem_access_unlock();
}

/* int filesize(int fd); */
static void filesize(struct intr_frame *f, void **argv) {
  int fd = *(int *) argv[0];
  /* -1 if file can not be opened*/
  int size_of_file = -1;

  filesystem_access_lock();

  /* Go through the list and see if this file descriptor exists. */
  struct file_descriptor *file_desc = file_descriptor_finder(fd);
  if (file_desc != NULL && file_desc->actual_file != NULL) {
    size_of_file = file_length(file_desc->actual_file);
  }

  filesystem_access_unlock();

  f->eax = size_of_file;
}

/* int read(int fd, void *buffer, unsigned size); */
static void read(struct intr_frame *f, void **argv) {
  check_pointer(*(void **) argv[1]);
  int fd = *(int *) argv[0];
  void *buffer = *(void **) argv[1];
  unsigned size = *(unsigned *) argv[2];
  int read_bytes = -1;


  if (fd == STDIN_FILENO) {
    char *input_buffer = (char *) buffer;
    for (int pos = 0; pos < size; pos++) {
      input_buffer[pos] = input_getc();
    }
    read_bytes = size;

  } else {
    filesystem_access_lock();
    struct file_descriptor *file_desc = file_descriptor_finder(fd);
    if (file_desc != NULL && file_desc->actual_file != NULL) {
      read_bytes = file_read(file_desc->actual_file, buffer, size);
    }
    filesystem_access_unlock();
  }

  f->eax = read_bytes;
}


/* int write(int fd, void *buffer, unsigned size); */
static void write(struct intr_frame *f, void **argv) {
  check_pointer(*(void **) argv[1]);
  int fd = *(int *) argv[0];
  const char *buffer = *(const char **) argv[1];
  unsigned size = *(unsigned *) argv[2];
  int bytes_written = 0;
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    bytes_written = size;
  } else {
    filesystem_access_lock();
    struct file_descriptor *file_desc = file_descriptor_finder(fd);
    if (file_desc != NULL && file_desc->actual_file != NULL) {
      bytes_written = file_write (file_desc->actual_file, buffer, size);
    }
    filesystem_access_unlock();
  }

  f->eax = bytes_written;
}

/* void seek(int fd, unsigned position); */
static void seek(struct intr_frame *_ UNUSED, void **argv) {
  int fd = *(int *) argv[0];
  off_t position = *(off_t *) argv[1];
  filesystem_access_lock();
  struct file_descriptor *file_desc = file_descriptor_finder(fd);
  if (file_desc != NULL && file_desc->actual_file != NULL) {
    file_seek(file_desc->actual_file, position);
  }
  filesystem_access_unlock();
}

/* unsigned tell(int fd); */
static void tell(struct intr_frame *f, void **argv) {
  int fd = *(int *) argv[0];
  filesystem_access_lock();
  struct file_descriptor *file_desc = file_descriptor_finder(fd);
  unsigned new_position = -1;
  if (file_desc != NULL && file_desc->actual_file != NULL) {
    new_position = file_tell(file_desc->actual_file);
  }
  filesystem_access_unlock();
  f->eax = new_position;
}

/* void close(int fd); */
static void close(struct intr_frame *_ UNUSED, void **argv) {
  int fd = *(int *) argv[0];
  filesystem_access_lock();
  struct file_descriptor *file_desc = file_descriptor_finder(fd);
  if (file_desc != NULL) {
    if (file_desc->actual_file != NULL) {
      file_close(file_desc->actual_file);
    }
    list_remove(&file_desc->thread_elem);
    free(file_desc);
  }
  filesystem_access_unlock();
}

static void check_pointer(void *pointer) {
  if (!valid_pointer(pointer)) {
    kill_process();
  }
}

static bool valid_pointer(void *pointer) {
  return pointer != NULL
         && is_user_vaddr(pointer)
         && pagedir_get_page(thread_current()->pagedir, pointer);
}

void kill_process(void) {
  struct thread *t = thread_current();
  t->exit_status = STATUS_KILLED;
  printf("%s: exit(%d)\n", t->name, t->exit_status);
  thread_exit();
}

static struct file_descriptor *file_descriptor_finder(int fd) {
  struct list_elem *elem;
  for (elem = list_begin(&thread_current()->file_descriptors);
       elem != list_end(&thread_current()->file_descriptors);
       elem = list_next(elem)) {
    struct file_descriptor *desc = list_entry(elem, struct file_descriptor,
                                              thread_elem);
    /* Return a pointer to file matching file descriptor. */
    if (desc->descriptor == fd) {
      return desc;
    }
  }
  return NULL;
}
