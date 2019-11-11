#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include <filesys/file.h>
#include <threads/synch.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"
#include "process.h"

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

static bool valid_pointer(void *);
static void kill(void);
static void check_pointer(void *pointer);

/* Array of function pointers the handler delegates to. */
static int (*fpa[13]) (void **argv) = {
    halt, exit, exec, wait, create, remove, open, filesize, read, write, seek, tell, close
};

/* Argument counts of handler function. */
static int argument_counts[] = {0, 1, 1, 1, 2, 1, 1, 1, 3, 3, 2, 1, 1};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
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
  char *cmd_line = (char *) argv[0];
  return process_execute(cmd_line);
}

/* int wait(pid_t pid); */
static int wait(void **argv) {
  tid_t child_tid = *(tid_t *) argv[0];
  printf("%d\n", child_tid);
  return process_wait(child_tid);
}

/* bool create(const char *file, unsigned initial_size); */
static int create(void **argv) {
  kill();
}

/* bool remove(const char *file); */
static int remove(void **argv) {
  kill();
}

/* int open(const char *file); */
static int open(void **argv) {
  kill();
}

/* int filesize(int fd); */
static int filesize(void **argv) {
  kill();
}

/* int read(int fd, void *buffer, unsigned size); */
static int read(void **argv) {
  kill();
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
  kill();
}

/* unsigned tell(int fd); */
static int tell(void **argv) {
  kill();
}

/* void close(int fd); */
static int close(void **argv) {
  kill();
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
  printf("%s: exit(%d)\n", thread_current()->name, STATUS_KILLED);
  thread_exit();
}
