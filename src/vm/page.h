#ifndef PAGE_H
#define PAGE_H

#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "threads/palloc.h"
#include "threads/thread.h"

#include "devices/block.h"
#include "lib/stdbool.h"
#include "filesys/off_t.h"
#include "filesys/file.h"
#include <debug.h>

#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

// DATA LOAD from binary file
#define VM_BIN 0
// DATA LOAD from mapping file(Memory Mapped file)
#define VM_FILE 1
// DATA LOAD from swap area (Swapping)
#define VM_ANON 2

#define SECTOR_SIZE (PGSIZE / BLOCK_SECTOR_SIZE)


struct lock filesys_lock;

struct vm_entry
{
  uint8_t vm_type; /* VM_BIN, VM_FILE, VM_ANON */
  void *vaddr; // virtual page number that vm_entry manage
  
  bool writable; // True -> writable, False -> not writable
  
  bool is_loaded;
  struct file *file; // file that mapped to vaddr
  
  off_t offset; // File Offset to Read
  uint32_t read_bytes; // data size to wrtie in virtual page
  uint32_t zero_bytes; // 0 filled size to write 0 in virtual page

  /* ++++ Project 3.4 swapping ++++ */
  size_t swap_slot; // swap slot

  /* Data Structure for vm_entry */
  struct hash_elem hash_elem; // Element for hash table
  /* ++++ Project 3.2 Memory Mapped File ++++ */
  struct list_elem mmap_elem;
};

struct mmap_file {
  int mapid;             // if mmap() success, return mapping id
  struct file* file;     // file object of mapping file
  struct list_elem elem; // list_elem of mmap_file
  // list head is mmap_list in the struct thread
  struct list vme_list;  // all vm_entry list about mmap_file
};

// for swapping
struct page {
  void *kaddr;           // physical address of page
  struct vm_entry *vme;  // reference to the virtual page object to which physical page is mapped
  struct thread *thread; // rreference to the thread that is using its physical page
  struct list_elem lru;  // field for list
  bool pin;
};



void vm_init(struct hash *vm);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
struct vm_entry * find_vme(struct hash *vm, void * vaddr);
void vm_destroy (struct hash *vm);
void destroy_mmap_list (struct list *mmap_list);

bool load_file(void *kaddr, struct vm_entry *vme);


// swapping
void swap_init(void);
void swap_in(void *kaddr, struct vm_entry *vme);
void swap_out(struct page*);

// frame
void lru_list_init (void);

void add_page_to_lru_list(struct page* page);
void del_page_from_lru_list(struct page* page);

struct page* alloc_page(enum palloc_flags flags, struct vm_entry *vme);
struct page* select_victim(struct list_elem *start);

void free_page(void *kaddr);
void __free_page(struct page* page);

void set_pin(void *);
void unset_pin(void *);

#endif