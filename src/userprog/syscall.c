#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


/* Additional */
#include <list.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"     // filesys_OOO()
#include "filesys/off_t.h"
#include "filesys/file.h"
#include "devices/shutdown.h" // shutdown_power_off()
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/page.h"


typedef void sig_func(void);

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* get stack pointer from intr_frame */

  /* get system call number from stack */
  set_pin(f->esp);
  int numbers = *(int*)f->esp;
  // TODO: add function that detect wrong addr (pg fault) 
  switch(numbers)
  {
    case SYS_HALT:                  
      halt();
      break;

    case SYS_EXIT:                   
      // one argument
      set_pin(f->esp+4);
      check_address(f->esp + 4, false);
      exit(*(int*)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_EXEC:                   
      set_pin(f->esp+4);
      check_address(f->esp + 4, false);
      f->eax = exec(*(const char**)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_WAIT:                  
      set_pin(f->esp+4);
      check_address(f->esp+4, false);
      f->eax = wait(*(pid_t*)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_CREATE:                 
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      check_address(f->esp + 4, false);
      check_address(f->esp + 8, false);
      lock_acquire(&filesys_lock);
      f->eax = create(*(const char**)(f->esp + 4), *(unsigned*)(f->esp + 8));
      lock_release(&filesys_lock);
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      break;

    case SYS_REMOVE:                 
      set_pin(f->esp+4);
      check_address(f->esp + 4, false);
      f->eax = remove(*(const char**)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_OPEN:                 
      set_pin(f->esp+4);
      check_address(f->esp + 4, false);
      lock_acquire(&filesys_lock);
      f->eax = open(*(const char**)(f->esp + 4));
      lock_release(&filesys_lock);
      unset_pin(f->esp+4);
      break;

    case SYS_FILESIZE:
      set_pin(f->esp+4);
      check_address(f->esp + 4,false);
      f->eax = filesize(*(int*)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_READ:
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      set_pin(f->esp+12);
      check_address(f->esp + 4, false);
      check_address(f->esp + 8, false);
      check_address(f->esp + 12, false);
      lock_acquire (&filesys_lock);
      check_buffer(*(void**)(f->esp+8), (void*)f->esp+8);
      //check_valid_buffer((void*)f->esp + 8, *(unsigned*)(f->esp + 12), true);
      f->eax = read(*(int*)(f->esp + 4), (void*)f->esp + 8, *(unsigned*)(f->esp + 12));
      lock_release (&filesys_lock);
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      unset_pin(f->esp+12);
      break;

    case SYS_WRITE: 
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      set_pin(f->esp+12);
      check_address(f->esp + 4, false);
      check_address(f->esp + 8, false);
      check_address(f->esp + 12, false);
      lock_acquire (&filesys_lock);
      check_buffer(*(void**)(f->esp+8), (void*)f->esp+8);
      f->eax = write(*(int*)(f->esp + 4), (void*)f->esp + 8, *(unsigned*)(f->esp + 12));
      lock_release (&filesys_lock);
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      unset_pin(f->esp+12);
      break;

    case SYS_SEEK:
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      check_address(f->esp + 4, false);
      check_address(f->esp + 8, false);
      seek(*(int*)(f->esp + 4), *(unsigned*)(f->esp + 8));
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      break;

    case SYS_TELL: 
      set_pin(f->esp+4);
      check_address(f->esp + 4, false);
      f->eax = tell(*(int*)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_CLOSE:  
      set_pin(f->esp+4);
      check_address(f->esp + 4, false);
      close(*(int*)(f->esp + 4));
      unset_pin(f->esp+4);
      break;

    case SYS_SIGACTION:
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      check_address(f->esp + 4, false);
      check_address(f->esp + 8, false);
      sigaction((int)*(uint32_t *)(f->esp+4),
		            *(sig_func **)(f->esp+8));
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      break;

    case SYS_SENDSIG:
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      check_address(f->esp + 4, false);
      check_address(f->esp + 8, false);
      sendsig((int)*(uint32_t *)(f->esp+4),
	            (int)*(uint32_t *)(f->esp+8));
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      break;
      
    case SYS_YIELD:  
      thread_yield();
      break;

    case SYS_MMAP:
      set_pin(f->esp+4);
      set_pin(f->esp+8);
      check_address(f->esp+4, false);
      check_address(f->esp+8, false);
	    f->eax = mmap((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp+8));
      unset_pin(f->esp+4);
      unset_pin(f->esp+8);
      break;

    case SYS_MUNMAP:
      set_pin(f->esp+4);
      check_address(f->esp+4, false);
      munmap((int)*(uint32_t *)(f->esp+4));
      unset_pin(f->esp+4);
      break;    
  }
  unset_pin(f->esp);
}


/* 1. Completed */
void 
halt(void)
{
  shutdown_power_off (); // shutdown pintos
}

/* 2. Completed */
void 
exit(int status)
{
  /* exit_status : 
     stores the status of the thread just before the current exit */
  thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t 
exec(const char* cmd_line)
{
  // create child process and execute program corresponds to cmd line
  tid_t tid = process_execute(cmd_line);
  return tid;
}

int 
wait(pid_t pid)
{
  // wait for termination of child process pid //& retrieve child's exit status
  return process_wait (pid);
}


/*============ file related system calls ==============*/
/* 3. Completed */
bool 
create(const char *file, unsigned initial_size)
{
  // file : name and path information for the file to create
  // initial_size : Size of file to create
  if (file == NULL)
  {
    exit(-1);
    return false;
  }
  // Create a file that corresponds to the file name and size
  return filesys_create(file, initial_size);
}

/* 4. Completed */
bool 
remove(const char *file)
{
  // Remove the file corresponding to the file name
  return filesys_remove(file);
}

int open(const char* file)
{
  if (file == NULL) 
    return -1;

  struct file* new_file = filesys_open(file);
  if (new_file == NULL) 
    return -1;
  struct thread * cur = thread_current();
  cur->fdt[cur->next_fd] = new_file;
  int fd = cur->next_fd;
  for (int i = 2; i < 128; i ++){
    if (cur->fdt[i] == NULL) {
      cur->next_fd = i;
      break;
    }
  }
  return fd;
}

int filesize(int fd)
{
  struct file* file = thread_current()->fdt[fd];
  return file_length(file);
}

int read(int fd, void *buffer, unsigned size)
{
  if (fd == 0)
  {
    const char* buf = *(char**)buffer;
    return input_getc(buf, size);
  }
  else
  {
    struct file* file = thread_current()->fdt[fd];
    const char* buf = *(char**)buffer;
    return file_read(file, buf, size);
  }
}

int write(int fd, const void *buffer, unsigned size)
{
  if (fd == 1){
    const char* buf = *(char**)buffer;
    putbuf(buf, size);
    return sizeof(buf);
  }
  else{
    struct file* file = thread_current()->fdt[fd];
    const char* buf = *(char**)buffer;
    return file_write(file, buf, size);
  }
}

void seek(int fd, unsigned position)
{
  struct file* file = thread_current()->fdt[fd];
  file_seek(file, position);
}

unsigned tell(int fd)
{
  struct file* file = thread_current()->fdt[fd];
  return file_tell(file);
}

void close(int fd)
{
  if(thread_current()->fdt[fd] == NULL) return -1;
  struct file* file = thread_current()->fdt[fd];
  file_close(file);
  thread_current()->fdt[fd] = NULL;
  for (int i = 2; i < 128; i ++)
  {
    if (thread_current()->fdt[i] == NULL) 
    {
      thread_current()->next_fd = i;
      break;
    }
  }
}




typedef void sig_func (void);
void sigaction(int signum, void(*handler)(void))
{
  thread_current()->parent_thread->sig_list[signum-1] = handler;
}

void sendsig(pid_t pid, int signum)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  for(e=list_begin(&cur->child_list);
      e!=list_end(&cur->child_list);e=list_next(e)){
    
    struct thread *child_t = list_entry(e, struct thread, child_elem);
    if(child_t->tid == pid){
      if(cur->sig_list[signum-1])
        printf("Signum: %d, Action: %p\n",signum, cur->sig_list[signum-1]);
    }
  }
}

void
check_address(void *esp, bool rw)
{
  if (esp >= PHYS_BASE) 
  {
    if (rw == true) lock_release(&filesys_lock);
    exit(-1);
  }
}

/* Virtual address valid test */
struct vm_entry * 
check_address_vm (void *addr)
{
  if(addr < (void *)0x08048000 || addr >= PHYS_BASE){
    exit(-1);
  }
  struct thread *cur = thread_current();
  // if addr exist in vm_entry, return vm_entry
  // use fine_vme()
  return find_vme(&(cur->vm), addr);
}

void check_buffer(void *addr, void *esp)
{
  if(addr < (void *)0x08048000 || addr >= PHYS_BASE){
    exit(-1);
  }
  if(esp - addr > 0x20 ){
    exit(-1);
  }
}

void
check_valid_buffer(void *buffer, unsigned size, bool to_write)
{
  void *upage;
  struct vm_entry *vme;
  /* from buffer to buffer+size, upage+=PGSIZE */
  for(upage = pg_round_down(buffer);upage < buffer+size; upage+=PGSIZE)
  {
    // check address is user? and call check_address() get vme
    vme = check_address_vm(upage);
    if(vme==NULL && vme->writable==false){
      lock_release(&filesys_lock);
      exit(-1);
    }
    // applied to vm_entry
    handle_mm_fault(vme);
  }
}

void
check_valid_string(const void* str)
{
  // if addr exist in vm_entry, return vm_entry
  // use fine_vme()
  if(check_address_vm(str)==NULL){
    lock_release(&filesys_lock);
    exit(-1);
  }
}



//////////////////////////////
/* +++++++++++++++++++++++++++++++++ */

int mmap(int fd, void *addr){
  // 1. Check argument 
  if(addr == NULL || pg_ofs(addr)!=0 )
    return -1;
  if (fd <=1)
    return -1;

  struct file *f;
  struct file *f_copy;
  struct thread *cur = thread_current();
  
  // 2. Returns the address of a file object by 
  //      searching the fd list of process 
  f = process_get_file(fd);

  //lock_acquire(&filesys_lock);

  if(f==NULL){
    //lock_release(&filesys_lock);
    return -1;
  }

  //3. Opens and returns a new file for the same inode as FILE.
  f_copy = file_reopen(f);
  // 4. Returns the size of FILE in bytes. 
  size_t f_length = file_length(f_copy);

  if( f_copy==NULL || f_length == 0 ){
    //lock_release(&filesys_lock);
    return -1;
  }

  //mmap_file create and initlize 
  struct mmap_file *mmap_f;
  mmap_f = malloc(sizeof(struct mmap_file));
  if(mmap_f == NULL)
    return -1;
  mmap_f->mapid = fd;
  mmap_f->file = f_copy;
  list_init(&(mmap_f->vme_list));


  uint32_t page_read_bytes;
  uint32_t page_zero_bytes;
  uint32_t page_offset = 0;

  for(size_t offset=0; offset<f_length; offset=offset+PGSIZE){
    void *upage = addr + offset;

    if((f_length - offset)/PGSIZE==0){
      page_read_bytes = f_length - offset;
      page_zero_bytes = PGSIZE - page_read_bytes;
    }
    else{
      page_read_bytes = PGSIZE;
      page_zero_bytes = 0;
    }

    //5. vm_entry create and initilize
    struct vm_entry *vme;
    vme = malloc(sizeof(struct vm_entry));
    vme->vm_type = VM_FILE;
    vme->vaddr = upage;
    vme->writable = true;
    vme->is_loaded= false;
    vme->file = mmap_f->file;
    vme->offset = page_offset;
    vme->read_bytes = page_read_bytes;
    vme->zero_bytes = page_zero_bytes;

    page_offset += page_read_bytes;

    if(!insert_vme(&(cur->vm), vme))
      return -1;
    list_push_back(&(mmap_f->vme_list),&(vme->mmap_elem));
  }

  list_push_back(&(cur->mmap_list),&(mmap_f->elem));
  //lock_release(&filesys_lock);
  return mmap_f->mapid;
}

void munmap(int mapping){
  
  struct thread *cur = thread_current();
  struct list_elem *e;
  /* 1. traverse mmap_list */
  for(e=list_begin(&cur->mmap_list);e!=list_end(&cur->mmap_list);e=list_next(e)){
    /* 2. get mmap_file from struct list_elem */
    struct mmap_file *mmap_f = list_entry(e, struct mmap_file, elem);
    /* 3. mapid match? */
    if(mmap_f->mapid==mapping){
      /*4. delete vm_entry and page table */
      do_munmap(mmap_f);
      /*5. delete mmap_f in mmap_list*/
      list_remove(&mmap_f->elem);
      /*6. file_close */
      file_close(mmap_f->file);
    }
  }
}

void
do_munmap(struct mmap_file *mmap_file){
  struct list_elem *mmap_vme;
  struct thread *cur = thread_current();

  for(mmap_vme=list_begin(&mmap_file->vme_list);mmap_vme!=list_end(&mmap_file->vme_list);mmap_vme=list_next(mmap_vme))
  {
    struct vm_entry *vme = list_entry(mmap_vme, struct vm_entry, mmap_elem);
    if(vme->is_loaded){
      void *kaddr = pagedir_get_page(cur->pagedir, vme->vaddr);
      // pd -> page table vpage -> address dirty return 1
      if (pagedir_is_dirty(cur->pagedir, vme->vaddr)){
        lock_acquire(&filesys_lock);
        file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
        lock_release(&filesys_lock);
      }
      // page table entry delete
      pagedir_clear_page(cur->pagedir, vme->vaddr);
      free_page(kaddr);
    }
    vme->is_loaded=false;
    list_remove(&vme->mmap_elem);
    //delete_vme(&(cur->vm), vme);
    //free(vme);
  }
}