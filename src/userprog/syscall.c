#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);
static bool valid_pointer(void *);

static int halt(void *, void *, void *);
static int exit(void *, void *, void *);
static int exec(void *, void *, void *);
static int wait(void *, void *, void *);
static int create(void *, void *, void *);
static int remove(void *, void *, void *);
static int open(void *, void *, void *);
static int filesize(void *, void *, void *);
static int read(void *, void *, void *);
static int write(void *, void *, void *);
static int seek(void *, void *, void *);
static int tell(void *, void *, void *);
static int close(void *, void *, void *);

/* Array of function pointers the handler delegates to. */
static int (*fpa[13]) (void *arg0, void *arg1, void *arg2) = {
    halt, exit, exec, wait, create, remove, open, filesize, read, write, seek, tell, close
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Here we rely on the safety of the syscall handler functions, i.e.
   * they will only try to dereference these pointers if the
   * prototype permits. */
  int *sp = f->esp;
  f->eax = fpa[*sp](sp + 1, sp + 2, sp + 3);

}

/* void halt(void); */
static int halt(void *_ UNUSED, void *__ UNUSED, void *___ UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

/* int exit(int status); */
static int exit(void *status_, void *_ UNUSED, void *__ UNUSED) {
  int status = *(int *) status_;
  printf("%d", status);
  thread_exit();
}

/* pid_t exec(const char *cmd_line); */
static int exec(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int wait(pid_t pid); */
static int wait(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* bool create(const char *file, unsigned initial_size); */
static int create(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* bool remove(const char *file); */
static int remove(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int open(const char *file); */
static int open(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int filesize(int fd); */
static int filesize(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int read(int fd, void *buffer, unsigned size); */
static int read(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* int write(int fd, void *buffer, unsigned size); */
static int write(void *fd_, void *buffer_, void *size_) {
  int fd = *(int *) fd_;
  const char *buffer = *(const char **) buffer_;
  unsigned size = *(unsigned *) size_;

  if (fd == 1) {
    putbuf(buffer, size);
  }

  //FIXME return;
}

/* void seek(int fd, unsigend position); */
static int seek(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* unsigned tell(int fd); */
static int tell(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

/* void close(int fd); */
static int close(void *a UNUSED, void *b UNUSED, void *c UNUSED) {

}

bool UNUSED valid_pointer(void *pointer UNUSED) {
  return pointer != NULL
                    && is_user_vaddr(pointer)
                    && pagedir_get_page(thread_current()->pagedir, pointer);
}
