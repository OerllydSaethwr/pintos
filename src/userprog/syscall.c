#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static bool valid_pointer(void *);

static void halt(void *, void *, void *);
static void exit(void *, void *, void *);
static void exec(void *, void *, void *);
static void wait(void *, void *, void *);
static void create(void *, void *, void *);
static void remove(void *, void *, void *);
static void open(void *, void *, void *);
static void filesize(void *, void *, void *);
static void read(void *, void *, void *);
static void write(void *, void *, void *);
static void seek(void *, void *, void *);
static void tell(void *, void *, void *);
static void close(void *, void *, void *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Array of function pointers the handler delegates to. */
  void (*fpa[13]) (void *arg0, void *arg1, void *arg2) = {
    halt, exit, exec, wait, create, remove, open, filesize, read, write, seek, tell, close
  };

  /* Here we rely on the safety of the syscall handler functions, i.e.
   * they will only try to dereference these pointers if the
   * prototype permits. */
  int *sp = f->esp;
  fpa[*sp](sp + 1, sp + 2, sp + 3);

}

/* void halt(void); */
static void halt(void *_ UNUSED, void *__ UNUSED, void *___ UNUSED) {
  shutdown_power_off();
}

/* int exit(int status); */
static void exit(void *status_, void *_ UNUSED, void *__ UNUSED) {
  int status = *(int *) status_;
  printf("%d", status);
  thread_exit();
}

/* pid_t exec(const char *cmd_line); */
static void exec(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int wait(pid_t pid); */
static void wait(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* bool create(const char *file, unsigned initial_size); */
static void create(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* bool remove(const char *file); */
static void remove(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int open(const char *file); */
static void open(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int filesize(int fd); */
static void filesize(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int read(int fd, void *buffer, unsigned size); */
static void read(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int write(int fd, void *buffer, unsigned size); */
static void write(void *fd_, void *buffer_, void *size_) {
  int fd = *(int *) fd_;
  const char *buffer = *(const char **) buffer_;
  unsigned size = *(unsigned *) size_;

  if (fd == 1) {
    putbuf(buffer, size);
  }

  //FIXME return;
}

/* void seek(int fd, unsigend position); */
static void seek(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* unsigned tell(int fd); */
static void tell(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* void close(int fd); */
static void close(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

bool UNUSED valid_pointer(void *pointer UNUSED) {
  return pointer != NULL && is_user_vaddr(pointer);
}
