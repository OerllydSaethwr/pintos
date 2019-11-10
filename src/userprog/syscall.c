#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <threads/synch.h>
#include <filesys/file.h>
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
static int tell(void **);
static int close(void **);

static void check_pointers(void ** argv, int argc);
static bool valid_pointer(void *);

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
  /* Here we rely on the safety of the syscall handler functions, i.e.
   * they will only try to dereference these pointers if the
   * prototype permits. */
  int *sp = f->esp;
  printf("%d\n", *(sp - 5));

  /* Creating argument array */
  void *argv[argument_counts[*sp]];
  int argc;
  for (argc = 0; argc < argument_counts[*sp]; argc++) {
    argv[argc] = sp + argc + 1;
  }

  /* Checking if pointers are valid */
  check_pointers(argv, argc);

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
  printf("%d", status);
  thread_exit();
  //FIXME
}

/* pid_t exec(const char *cmd_line); */
static int exec(void **argv) {

}

/* int wait(pid_t pid); */
static int wait(void **argv) {

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

}

/* int write(int fd, void *buffer, unsigned size); */
static int write(void **argv) {
  int fd = *(int *) argv[0];
  const char *buffer = *(const char **) argv[1];
  unsigned size = *(unsigned *) argv[2];

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
  }

  //FIXME return;
}

/* void seek(int fd, unsigend position); */
static int seek(void **argv) {

}

/* unsigned tell(int fd); */
static int tell(void **argv) {

}

/* void close(int fd); */
static int close(void **argv) {

}

static void check_pointers(void **argv, int argc) {
  for (int i = 0; i < argc; i++) {
    if (!valid_pointer(argv[i])) {
      printf("Invalid pointer!\n");
      thread_exit();
    }
  }
}

static bool valid_pointer(void *pointer) {
  return pointer != NULL
                    && is_user_vaddr(pointer)
                    && pagedir_get_page(thread_current()->pagedir, pointer);
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


