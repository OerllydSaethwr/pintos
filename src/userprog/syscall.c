#include <devices/input.h>
#include <devices/shutdown.h>
#include <filesys/file.h>
#include <filesys/filesys.h>
#include <stdio.h>
#include <threads/synch.h>
#include <threads/vaddr.h>
#include "pagedir.h"
#include "process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"

static void check_pointer (void *pointer);

static void check_string_pointer (const char *string);

static void close (void **);

static void create (void **);

static void exec (void **);

static void exit (void **);

static void filesize (void **);

static void halt (void **);

static void open (void **);

static void read (void **);

static void remove (void **);

static void seek (void **);

static void syscall_handler (struct intr_frame *);

static void tell (void **);

static bool valid_pointer (void *);

static void wait (void **);

static void write (void **);

static struct file_descriptor *file_descriptor_finder (int fd);

static struct lock filesystem_lock;

/* All delegate functions have the same function signatures (take the same
 * arguments), to allow as to use an array of function pointers and delegate
 * in one line */

/* Array of function pointers the handler delegates to. */
static void (*fpa[13]) (void **argv) = {
  halt, exit, exec, wait, create, remove, open, filesize, read, write, seek,
  tell, close
};

/* Argument counts of handler function. */
static int argument_counts[] = {ARG_NUM_HALT, ARG_NUM_EXIT, ARG_NUM_EXEC,
                                ARG_NUM_WAIT, ARG_NUM_CREATE, ARG_NUM_REMOVE,
                                ARG_NUM_OPEN, ARG_NUM_FILESIZE, ARG_NUM_READ,
                                ARG_NUM_WRITE, ARG_NUM_SEEK, ARG_NUM_TELL,
                                ARG_NUM_CLOSE};

void syscall_init (void) {
  lock_init (&filesystem_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f) {
  int *sp = f->esp;
  check_pointer (sp);

  /* Creating argument array */
  int argc = argument_counts[*sp];
  void *argv[argc + 1];
  for (int i = 0; i < argc; i++) {
    argv[i] = sp + i + 1;
  }
  argv[argc] = &f->eax;

  /* Checking if pointers are valid */
  for (int i = 0; i < argc; ++i) {
    check_pointer (argv[i]);
  }

  /* Delegating to specific syscall */
  fpa[*sp] (argv);
}

static void halt (void **_ UNUSED) {
  shutdown_power_off ();
}

static void exit (void **argv) {
  int status = *(int *) argv[0];
  int *eax = (int *) argv[1];
  *eax = status;
  struct thread *t = thread_current ();
  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, status);
  thread_exit ();
}

static void exec (void **argv) {
  const char *cmd_line = *(char **) argv[0];
  int *eax = (int *) argv[1];
  check_string_pointer (cmd_line);
  tid_t pid = process_execute (cmd_line);
  *eax = pid;
}

static void wait (void **argv) {
  tid_t child_tid = *(tid_t *) argv[0];
  int *eax = (int *) argv[1];
  *eax = process_wait (child_tid);
}

static void create (void **argv) {
  const char *file = *(const char **) argv[0];
  unsigned initial_size = *(unsigned *) argv[1];
  int *eax = (int *) argv[2];
  check_string_pointer (file);
  lock_acquire (&filesystem_lock);
  *eax = filesys_create (file, initial_size);
  lock_release (&filesystem_lock);
}

static void remove (void **argv) {
  const char *file = *(const char **) argv[0];
  int *eax = (int *) argv[1];
  check_string_pointer (file);
  lock_acquire (&filesystem_lock);
  *eax = filesys_remove (file);
  lock_release (&filesystem_lock);
}

static void open (void **argv) {
  const char *file = *(const char **) argv[0];
  int *eax = (int *) argv[1];
  check_string_pointer (file);
  lock_acquire (&filesystem_lock);
  struct file *opened_file = filesys_open (file);
  /* Allocate memory for new file_discriptor struct and add pointer to it to
   * HashTable*/
  if (opened_file != NULL) {
    struct file_descriptor *new = malloc (sizeof (struct file_descriptor));
    /* Increment descriptor value to ensure each new file has a unique value */
    new->descriptor = ++(thread_current ()->curr_file_descriptor);
    new->actual_file = opened_file;
    hash_insert (&thread_current ()->file_hash_descriptors,
                 &new->thread_hash_elem);
    *eax = new->descriptor;
  } else {
    *eax = INVALID;
  }
  lock_release (&filesystem_lock);
}

static void filesize (void **argv) {
  int fd = *(int *) argv[0];
  int *eax = (int *) argv[1];
  /* -1 if file can not be opened*/
  int size_of_file = INVALID;
  lock_acquire (&filesystem_lock);

  /* Lookup file descriptor in HashTable and calculate size if file exists*/
  struct file_descriptor *file_desc = file_descriptor_finder (fd);
  if (file_desc != NULL && file_desc->actual_file != NULL) {
    size_of_file = file_length (file_desc->actual_file);
  }

  lock_release (&filesystem_lock);
  *eax = size_of_file;
}

static void read (void **argv) {
  check_pointer (*(void **) argv[1]);
  int fd = *(int *) argv[0];
  void *buffer = *(void **) argv[1];
  unsigned size = *(unsigned *) argv[2];
  int *eax = (int *) argv[3];

  /* -1 if file can not be opened*/
  unsigned read_bytes = INVALID;
  lock_acquire (&filesystem_lock);

  /* Read into buffer from STDIN */
  if (fd == STDIN_FILENO) {
    char *input_buffer = (char *) buffer;
    for (unsigned pos = 0; pos < size; pos++) {
      input_buffer[pos] = input_getc ();
    }
    read_bytes = size;
  } else {
    /* Lookup file descriptor in HashTable and read into buffer if file exists*/
    struct file_descriptor *file_desc = file_descriptor_finder (fd);
    if (file_desc != NULL && file_desc->actual_file != NULL) {
      read_bytes = file_read (file_desc->actual_file, buffer, size);
    }
  }
  lock_release (&filesystem_lock);
  *eax = read_bytes;
}


static void write (void **argv) {
  check_pointer (*(void **) argv[1]);
  int fd = *(int *) argv[0];
  const char *buffer = *(const char **) argv[1];
  unsigned size = *(unsigned *) argv[2];
  int *eax = (int *) argv[3];
  int bytes_written = 0;
  lock_acquire (&filesystem_lock);

  /* Write out into STDOUT*/
  if (fd == STDOUT_FILENO) {
    putbuf (buffer, size);
    bytes_written = size;
  } else {
    /* Lookup file descriptor in HashTable & write into buffer if file exists*/
    struct file_descriptor *file_desc = file_descriptor_finder (fd);
    if (file_desc != NULL && file_desc->actual_file != NULL) {
      bytes_written = file_write (file_desc->actual_file, buffer, size);
    }
  }
  lock_release (&filesystem_lock);
  *eax = bytes_written;
}

static void seek (void **argv) {
  int fd = *(int *) argv[0];
  off_t position = *(off_t *) argv[1];
  lock_acquire (&filesystem_lock);

  /* Lookup file descriptor in HashTable & seek to position if file exists*/
  struct file_descriptor *file_desc = file_descriptor_finder (fd);
  if (file_desc != NULL && file_desc->actual_file != NULL) {
    file_seek (file_desc->actual_file, position);
  }
  lock_release (&filesystem_lock);
}

static void tell (void **argv) {
  int fd = *(int *) argv[0];
  int *eax = (int *) argv[1];
  unsigned new_position = INVALID;
  lock_acquire (&filesystem_lock);

  /* Lookup file descriptor in HashTable and  return current position if file
   * exists*/
  struct file_descriptor *file_desc = file_descriptor_finder (fd);
  if (file_desc != NULL && file_desc->actual_file != NULL) {
    new_position = file_tell (file_desc->actual_file);
  }
  lock_release (&filesystem_lock);
  *eax = new_position;
}

static void close (void **argv) {
  int fd = *(int *) argv[0];
  lock_acquire (&filesystem_lock);

  /* Find file in HashTable and if it exsists close it, remove it from the
   * table and free memory */
  struct file_descriptor *file_desc = file_descriptor_finder (fd);
  if (file_desc != NULL) {
    if (file_desc->actual_file != NULL) {
      file_close (file_desc->actual_file);
    }
    hash_delete (&thread_current ()->file_hash_descriptors,
                 &file_desc->thread_hash_elem);
    /* Free previously malloced memory for file */
    free (file_desc);
  }
  lock_release (&filesystem_lock);
}

static void check_string_pointer (const char *string) {
  check_pointer ((void *) string);
  check_pointer ((void *) string + sizeof (string));
}

static void check_pointer (void *pointer) {
  if (!valid_pointer (pointer)) {
    kill_process ();
  }
}

static bool valid_pointer (void *pointer) {
  return pointer != NULL
         && is_user_vaddr (pointer)
         && pagedir_get_page (thread_current ()->pagedir, pointer);
}

void kill_process (void) {
  struct thread *t = thread_current ();
  t->exit_status = STATUS_KILLED;
  printf ("%s: exit(%d)\n", t->name, t->exit_status);
  thread_exit ();
}

/* A function to search HashTable for given file descriptor value. Returns
 * file descriptor struct if found, otherwise returns NULL */
static struct file_descriptor *file_descriptor_finder (int fd) {
  struct file_descriptor temp_fd;
  struct hash_elem *elem;
  temp_fd.descriptor = fd;
  elem = hash_find (&thread_current ()->file_hash_descriptors,
                    &temp_fd.thread_hash_elem);
  if (elem != NULL) {
    return hash_entry (elem, struct file_descriptor, thread_hash_elem);
  }

  return NULL;
}
