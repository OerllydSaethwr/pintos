#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads/synch.h>
#include <vm/mmap.h>
#include <vm/utils.h>
#include "vm/frame.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
struct lock file_lock;
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t process_execute (const char *file_name) {
  if (strlen (file_name) > MAX_STRING_LENGTH) {
    return TID_ERROR;
  }

  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Make structure for start_process to use,
   * makes sure process_exit doesn't return before load returns. */
  struct start_proc_aux process;
  process.file_name = fn_copy;
  sema_init (&process.load_finish, 0);
  process.success = false;
  void *aux = &process;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_copy, PRI_DEFAULT, start_process, aux);

  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }

  /* Wait for load to finish. */
  sema_down (&process.load_finish);
  if (process.success) {
    return tid;
  }

  return TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *aux_) {
  struct start_proc_aux *aux = (struct start_proc_aux *) aux_;
  char *file_name = aux->file_name;
  struct intr_frame if_;
  bool success;

  /* Tokenizes fn_copy */
  int cnt = 0;
  char *token, *save_p;
  for (token = strtok_r (file_name, " ", &save_p); token != NULL;
       token = strtok_r (NULL, " ", &save_p)) {
    cnt++;
  }

  /* Creates an array of pointers that each point to the tokenized strings */
  char *tokenized[cnt];
  save_p = file_name;

  for (int i = 0; i < cnt; i++) {
    tokenized[i] = save_p;
    save_p += strlen (save_p) + sizeof (char);
    while (*save_p == ' ') {
      save_p++;
    }
  }

  /* Thread name stores the process name. */
  strlcpy (thread_current ()->name, tokenized[0],
           sizeof (thread_current ()->name));

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  lock_init(&file_lock);
  success = load (file_name, &if_.eip, &if_.esp);
  aux->success = success;

  /* Signal process_execute that load has finished. */
  sema_up (&aux->load_finish);

  /* Push arguments to stack */
  if (success) {

    /* Push arg strings */
    int tknzd_size = cnt;

    for (--cnt; cnt >= 0; cnt--) {
      char *curr = tokenized[cnt];
      if_.esp -= strlen (curr) + sizeof (char);
      strlcpy (if_.esp, curr, strlen (curr) + 1);

      /* Update our pointers to point to the strings to the stack,
       * this will make pushing the pointers easier later.
       * We don't lose the original pointer since file_name keeps
       * track of it, so we can still free the page */
      tokenized[cnt] = if_.esp;
    }

    /* Push 0 separator */
    if_.esp -= sizeof (void *);
    *((int *) if_.esp) = 0;

    /* Push pointers to arg strings */
    for (cnt = tknzd_size - 1; cnt >= 0; cnt--) {
      if_.esp -= sizeof (char *);
      *((char **) if_.esp) = tokenized[cnt];
    }

    /* Push array pointer */
    char **argv = if_.esp;
    if_.esp -= sizeof (char **);
    *((char ***) if_.esp) = argv;

    /* Push argc */
    if_.esp -= sizeof (int);
    *((int *) if_.esp) = tknzd_size;

    /* Push fake return address */
    if_.esp -= sizeof (void *);
    *((int *) if_.esp) = 0;

  }

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid) {
  struct thread *t = thread_current ();
  struct thread *child_t = find_thread_by_tid (child_tid);
  if (child_t == NULL || child_t->parent != t->tid || child_t->been_waited_on) {
    return INVALID_WAIT;
  }

  /* Wait for child to die. */
  sema_down (&child_t->waiting_parent_sema);
  child_t->been_waited_on = true;
  return child_t->exit_status;
}

/* Removes remaining entries from HashMap. */
static void delete_remaining_hash (struct hash_elem *e, void *aux UNUSED) {
  struct file_descriptor *fd = hash_entry (e, struct file_descriptor,
                                           thread_hash_elem);
  file_close (fd->actual_file);
  free (fd);
}

/* Free the current process's resources. */
void process_exit (void) {
  struct thread *cur = thread_current ();
  uint32_t *pd;

  hash_destroy (&cur->file_hash_descriptors, delete_remaining_hash);
  hash_destroy (&cur->mmap_table, unmap_hash);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    file_close (cur->executable);
    pagedir_destroy (pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment(off_t ofs, uint8_t *upage, uint32_t read_bytes,
                        uint32_t zero_bytes, page_type type,
                        struct supp_entry *supp_entry);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp) {
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  int i;
  bool success = false;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) {
    goto done;
  }

  process_activate ();
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  file_deny_write (file);
  t->executable = file;
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for ( i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
//              if (!load_segment (file, file_page, (void *) mem_page,
//                                 read_bytes, zero_bytes, writable))
//                goto done;
//              printf("----------------------------------------\n"
//                     "| Creating new supp_entry with\n"
//                     "| read_bytes: %d\n"
//                     "| zero_bytes: %d\n"
//                     "| offset: %d\n"
//                     "| vaddr: %p\n"
//                     "| writable: %d"
//                     "----------------------------------------\n", read_bytes, zero_bytes, file_page, (void *) mem_page, writable);
              struct supp_entry *supp_entry = malloc(sizeof(struct supp_entry));
              supp_entry->file = file;
              supp_entry->read_bytes = read_bytes;
              supp_entry->writeable = writable;
              supp_entry->segment_offset = file_page;
              supp_entry->initial_page = mem_page;
              supp_entry->type = writable ? EXEC_DATA : EXEC_CODE;
              supp_entry->map_entry = NULL;
              create_fake_entries((void *) mem_page, read_bytes, zero_bytes, supp_entry);
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(off_t ofs, uint8_t *upage, uint32_t read_bytes,
             uint32_t zero_bytes, page_type type,
             struct supp_entry *supp_entry)
{

  struct file *file = supp_entry->file;
  ofs += supp_entry->segment_offset;
  bool writable = supp_entry->writeable;

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  //printf("loading page into: %p\n", upage);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      //TODO: check 
      uint8_t *kpage = falloc_get_frame(upage, PAL_USER, type, file, supp_entry->map_entry);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          falloc_free_frame (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
        printf("writable:  %d", writable);
          falloc_free_frame (kpage);
          return false; 
        }

      /* Advance. */
//      printf("read_bytes: %d, will be decremented by %lu\n", read_bytes, page_read_bytes);
//      printf("zero_bytes: %d, will be decremented by %lu\n", zero_bytes, page_zero_bytes);
//      printf("*********\n");
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

bool load_segment_lazy(struct supp_entry *supp_entry, uint8_t *upage,
                       page_type type) {
  uint32_t offset = (uint32_t) upage - supp_entry->initial_page;

  uint32_t read_bytes = offset > supp_entry->read_bytes ? 0 : (supp_entry->read_bytes - offset);
  read_bytes = read_bytes > PGSIZE ? PGSIZE : read_bytes;
  uint32_t zero_bytes = PGSIZE - read_bytes;

//  printf("Lazy loading entry at %p\n", upage);

  ASSERT(read_bytes + zero_bytes == PGSIZE);

  bool success = load_segment(offset, upage, read_bytes, zero_bytes, type, supp_entry);
  return success;
}

bool create_fake_entries(uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, struct supp_entry* supp_entry) {
  uint32_t cnt = 0;
  uint32_t last_addr = 0;
  while (read_bytes > 0 || zero_bytes > 0)
  {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    pagedir_set_page(thread_current()->pagedir, upage, supp_entry, supp_entry->writeable, FAKE);

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    last_addr = (uint32_t) upage;
    upage += PGSIZE;
    cnt++;
  }

  printf("Creating %u fake entries\n", cnt);
  printf("Last entry is at %p\n", (void *) last_addr);

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = falloc_get_frame(((uint8_t *) PHYS_BASE) - PGSIZE, PAL_USER, STACK,
                           NULL, NULL);

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        falloc_free_frame (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  //printf("installing page \n");

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */

  if (pagedir_get_page (t->pagedir, upage) == NULL) {
    //printf("checking get page\n");
    bool page = pagedir_set_page (t->pagedir, upage, kpage, writable, USER);
    //printf("setting page\n");
    return page;
  }
  return false;
  /*return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable, USER));*/
}