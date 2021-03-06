#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Additional */
#include "threads/malloc.h" // for malloc, free
#include "vm/page.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* ++++ Project 2.1 Argument Passing ++++ */
  char *prog_name;
  char *saveptr1;
  /* +++++++++++++++++++++++++++++++++++++ */


  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  prog_name = palloc_get_page(0); // copy 4096byte to fn_copy, prog_name
  fn_copy = palloc_get_page (0);

  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (prog_name, file_name, PGSIZE);
  
  /* ++++ Project 2.1 Argument Passing ++++ */
  strtok_r(prog_name, " ", &saveptr1); // for revised project3

  // printf("thread_Create : %s\n",prog_name); // for debug
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, fn_copy);
  /* ++++ Project 2.1 Argument Passing ++++ */
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct thread *child_thread = NULL;


  /* +++++++++++++++++++++++++++++++++++++ */

  for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e=list_next(e))
  {
    child_thread = list_entry (e, struct thread, child_elem);
    if (child_thread->tid == tid) 
    {
      //child_thread = list_entry (e, struct thread, child_elem);
      break;
    }
  }

  if (child_thread == NULL)
    return -1;

  sema_down(&child_thread->sema_for_exec);

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy); 
    tid = -1;
  }
  palloc_free_page(prog_name);
  return child_thread->tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  //printf("start_process\n"); //for debug
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  
  /* ++++ Project2.1 Argument Passing  ++++ */
  // 1. declare variable
  char **parse = malloc(sizeof(char*)*50);
  char *token, *save_ptr;
  int argu_count = 0;

  // 2. first prog name 
  token = strtok_r(file_name, " ", &save_ptr);
  // printf("token : %s\n",token); //for debug

  while(token!=NULL){
    parse[argu_count] = token;
    argu_count++;
    token = strtok_r(NULL, " ", &save_ptr);
  }
  /* ++++++++++++++++++++++++++++++++++++++ */

  /*++++ Project 3.1 for vm_entry ++++*/
  // initialize hash table
  struct thread *t = thread_current ();
  vm_init(&(t->vm));
  /*++++++++++++++++++++++++++++++++++*/



  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  /* if_.esp is stack pointer */
  /* 1. load program to memory that called "file_name" */
  success = load (file_name, &if_.eip, &if_.esp);
  // printf("load : %s\n",file_name); // for debug
  /* 2.  */
  sema_up(&thread_current()->sema_for_exec);
  thread_current()->load_status = success;
  /* If load failed, quit. */
  if (!success) // +++++++
  {
    thread_current()->tid = TID_ERROR;
    exit(-1); //++++
  } 
    
  /* ++++ Project2.1 Argument Passing  ++++ */
  argument_stack(parse, argu_count, &if_.esp);
  // for debugging
  //hex_dump(if_.esp, if_.esp, PHYS_BASE -if_.esp, true);
  free(parse); // above malloc free
  /* ++++++++++++++++++++++++++++++++++++++ */
  palloc_free_page(file_name);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  
  /* 2. start user program  */
  // Copy the user program context stored in the interrupt frame (if_) to the user stack 
  // and change the execution flow to the 'intr_exit' location
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
int
process_wait (tid_t child_tid UNUSED) 
{
  /* ++++ Project 2.4 wait implement ++++ */
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct thread *child_thread = NULL;

  // Search to know information of process
  for (e = list_begin(&cur->child_list); e!= list_end(&cur->child_list); e=list_next (e))
  {
    if (list_entry (e, struct thread, child_elem)->tid == child_tid){
      
      child_thread = list_entry (e, struct thread, child_elem);
      /* Error, if the process calls wait() twice */
      if (child_thread->called_wait) 
        return -1;
      /* called wait() */
      child_thread->called_wait = 1;
      
      /* If thread is in exit state, 
         child_thread is exit_status is returned */
      /*if (child_thread->thread_exit) 
        return child_thread->exit_status;*/
      break;
    }
  }

  // Abnormal exit
  if (child_thread == NULL)
    return -1;

  // Wait for the parent process until the child process is exit
  sema_down(&child_thread->sema_for_wait); 
  
  if (child_thread->thread_exit == 0)
    return -1;
  
  list_remove(&child_thread->child_elem);
  int status = child_thread->exit_status;
  palloc_free_page(child_thread);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  // palloc_free_page(cur->fdt)
  /*++++ Project 3.1 for vm_entry ++++*/
  //#ifdef VM
  destroy_mmap_list(&cur->mmap_list);
  vm_destroy(&(cur->vm));
  //#endif

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /*change*/
  if (cur->parent_thread != NULL) 
    sema_up(&cur->sema_for_wait);
  
  cur->thread_exit = 1;
  
  // multi-oom
  file_close(cur->running_file);
  for (int i = 0; i < 128; i ++)
    file_close(cur->fdt[i]);
  
  
  struct list_elem *e;
  struct thread *child_thread = NULL;

  /*for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list); e = list_next (e))
  {
      child_thread = list_entry (e, struct thread, child_elem);
      process_wait(child_thread->tid);
  }*/
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
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  // esp : stack pointer address
  // eip : text(code) segment start address
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  // 1. create page table for thread (user process)
  // pagedir : page directory -> page table -> code, data segment
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  // Change value of PDBR(cr3) register 
  // to running thread's page table address
  process_activate (); // page table activate
  lock_acquire(&filesys_lock);
  /* Open executable file */
  file = filesys_open (file_name); // program file open
  lock_release(&filesys_lock);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      thread_current()->tid = -1;
      goto done; 
    }

  /* ++++ 2.5 File deny ++++ */
  t->running_file = file;
  file_deny_write(t->running_file);
  /* Read and verify executable header. */
  /* Read ELF header information from memory */
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
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      /* Read file and save phdr */
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
              /* load file to memory according to  */
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  /* stack intialize */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

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
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

/* ++++ Project 3.1 vm_entry create -> field set -> insert hash table ++++ */
 //ifdef VM
      /* Create vm_entry(Use malloc) */
      struct vm_entry *vme;
      vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
      
      /*Setting vm_entry memebers*/
      vme->vaddr = upage;
      vme->vm_type = VM_BIN;
      vme->writable = writable;
      vme->file = file;
      
      vme->offset = ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      
      vme->is_loaded = false;

       /*Add vm_entry to hash table by insert_vme() */
      struct thread *cur = thread_current ();
      if(insert_vme(&cur->vm,vme)==false)
        return false;
//#else     
      /* Get a page of memory. */
      //uint8_t *kpage = palloc_get_page (PAL_USER);
      //if (kpage == NULL)
      //  return false;

      /* Load this page. */
      //if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //  {
      //    palloc_free_page (kpage);
      //    return false; 
      //  }
      //memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      //if (!install_page (upage, kpage, writable)) 
      //  {
      //    palloc_free_page (kpage);
      //    return false; 
      //  }
      
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs+= page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  //uint8_t *kpage;
  struct page *kpage;
  bool success = false;
  struct vm_entry *vme = (struct vm_entry *) malloc(sizeof(struct vm_entry));
  kpage = alloc_page(PAL_USER | PAL_ZERO, vme);
  //kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }

/* ++++ Project 3.1 stack vm_entry create -> field -> insert ++++ */
#ifdef VM
  struct thread *cur = thread_current ();

  vme->vaddr = pg_round_down( ((uint8_t *)PHYS_BASE) - PGSIZE );
  vme->vm_type = VM_ANON;
  vme->writable=true;
  vme->is_loaded = true;
  
  // new vm_entry add to hash table.
  if(!insert_vme(&(cur->vm),vme))
    return false;
#endif

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
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}



/* ++++ Project2.1 Argument Passing ++++ */
void argument_stack(char* argv[], int argc, void **esp){
  char *argu_addr[128];
  
  /* 1. NAME and ARGUMENT of program push */
  for(int i = argc-1; i>=0; i--){
    //printf("%s strlen: %d\n",*(argv+i), strlen(argv[i]));
    if(argv[i] != 0){
      for(int j = strlen(argv[i]); j>=0; j--){
	      *esp = *esp - 1;
	      **(char **)esp = argv[i][j]; //null character
      }
      argu_addr[i] = *(char **)esp; // esp's address put to list.
    } 
  }

  /* 2. insert padding for word-align */
  while ((int)(*esp)%4!=0){
    *esp = *esp -1;
    **(uint8_t **)esp = 0; // word-align
  }

  /* 3. address of NAME and ARGUMENT push */
  for (int i = argc; i>=0; i--){
    *esp = *esp -4;
    if(i==argc)
      memset(*esp, 0, sizeof(char **));
    else
      memcpy(*esp, &argu_addr[i], sizeof(char*));
  }

  /* 4. push address of argv */
  memcpy(*esp-4, &(*esp), sizeof(char**));
  *esp = *esp -4;

  /* 5. push argc (argument number) */
  *esp = *esp -4;
  **(int **)esp = argc;

  /* 6. fake address(0) saved*/
  *esp = *esp - 4;
  memset(*esp, 0, sizeof(void *));
}

/* ++++ Project 3.1 page fault handler ++++ */
bool 
handle_mm_fault(struct vm_entry *vme)
{
  if(vme == NULL){
      return false;
  }
  if(vme->is_loaded){
    return true;
  }
  /* 1. physical memory allocation */
  //uint8_t *kpage = palloc_get_page(PAL_USER);
  struct page *kpage = alloc_page(PAL_USER,vme);
  if(kpage == NULL)
      return false;

  /* 2. get vm type of  vm_entry */
  int type = vme->vm_type;

  /* 3. Check the vm_entry type */
  switch (type){
      case VM_BIN :
        /* 4. Load file to physical memory */
        if(!load_file(kpage->kaddr,vme)){
            free_page(kpage);
            //palloc_free_page(kpage);
            return false;
        }
        /* 5. page table set up, mapping physcial page and virtual page  */
        break;

      case VM_FILE :
        /* 4. Load file to physical memory */
        if(!load_file(kpage->kaddr,vme)){
          free_page(kpage);
          //palloc_free_page(kpage);
          return false;
        }
        break;

      case VM_ANON :
        swap_in(kpage->kaddr, vme);
        break;
  }

  if(!install_page(vme->vaddr, kpage->kaddr, vme->writable)){
    free_page(kpage);
    //palloc_free_page(kpage);
    return false;
  }

  vme->is_loaded=true;
  return true;
}



/* ++++ Project 3.2 Memory Mapped file +++++ */
// Return the address of a file object by
// searching the fd list of process
struct file *
process_get_file(int fd) {
  struct thread *cur = thread_current();

  for (int i = 2; i < cur->next_fd ; i++) {
    if (i == fd){
      return cur->fdt[fd]; // struct file
    }
  }
  return NULL;
}
/* ++++++++++++++++++++++++++++++++ */