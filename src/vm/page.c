#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <debug.h>
#include <string.h>

#include "page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "lib/stdbool.h"
#include "lib/kernel/hash.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
//#include "frame.h"
#include <stddef.h> // size_t


// frame
struct list lru_list; //global variable : Manage physical pages in use as a list of page
extern struct list lru_list;
struct list_elem *lru_clock;

// swapping
struct lock swap_lock;
struct block *block_swap;
extern struct block *block_swap;

struct bitmap *swap_map;
extern struct bitmap *swap_bitmap;



/*++++ Project 3.1 for vm_entry ++++*/
static unsigned 
vm_hash_func(const struct hash_elem *e, void *aux)
{
    struct vm_entry *vme = hash_entry (e, struct vm_entry, hash_elem);
    return hash_int(vme->vaddr);
}

static bool
vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
    struct vm_entry *vme_a = hash_entry (a, struct vm_entry, hash_elem);
    struct vm_entry *vme_b = hash_entry (b, struct vm_entry, hash_elem);
    return (vme_a->vaddr)<(vme_b->vaddr); // a>b : true, a<=b false
}

void 
vm_init(struct hash *vm)
{
    hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

bool 
insert_vme(struct hash *vm, struct vm_entry *vme)
{
    return hash_insert(vm, &(vme->hash_elem)) == NULL;
}

bool 
delete_vme(struct hash *vm, struct vm_entry *vme){
    return hash_delete(vm, &(vme->hash_elem)) != NULL;
}

struct vm_entry * 
find_vme(struct hash *vm, void * vaddr){
    struct vm_entry tmp;
    struct hash_elem *tmp_elem;
    tmp.vaddr = pg_round_down(vaddr); // page number only not offset
    // down
    tmp_elem = hash_find(vm, &tmp.hash_elem);
    //* pg_round_down (const void *va)
    //     return (void *) ((uintptr_t) va & ~PGMASK);
    if (tmp_elem == NULL) 
        return NULL;
    return hash_entry(tmp_elem, struct vm_entry, hash_elem);
}

void
vme_destroy_hash_elem(const struct hash_elem *he, void *aux)
{
    struct vm_entry *vme;
    vme = hash_entry(he, struct vm_entry, hash_elem);
    /*add*/
    struct page * page_destroy;
    struct list_elem *e;
    if(vme->is_loaded){
        for(e=list_begin(&lru_list);e!=list_end(&lru_list);e=list_next(e)){
          page_destroy = list_entry(e, struct page, lru);
          if(page_destroy->vme == vme){
              break;
          }
        }
        pagedir_clear_page(page_destroy->thread->pagedir, page_destroy->vme->vaddr);
        free_page(page_destroy->kaddr);
      
    }
    free(vme);
}

void 
vm_destroy (struct hash *vm){
    hash_destroy(vm, vme_destroy_hash_elem);
}


bool
load_file(void *kaddr, struct vm_entry *vme){
  if(file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset)==vme->read_bytes){
    memset(kaddr+vme->read_bytes, 0, vme->zero_bytes);
    return true;
  }
  return false;
}

void 
destroy_mmap_list (struct list *mmap_list){
  struct list_elem *e;
  struct list_elem *mmap_e;
  struct vm_entry *vme;
  for(struct list_elem *e = list_begin(mmap_list);e!=list_end(mmap_list);e=list_next(e))
  {
    struct mmap_file *m_file = list_entry(e, struct mmap_file, elem);
    for(struct list_elem *e2 = list_begin(&m_file->vme_list);e2!=list_end(&m_file->vme_list);e2=list_next(e2)){
      struct vm_entry *vme = list_entry(e2, struct vm_entry, mmap_elem);
      if(vme->is_loaded==true){
        list_remove(&vme->mmap_elem);
        vme->is_loaded=false;
      }
    }
    list_remove(&m_file->elem);
    file_close(m_file->file);
  }
}


////////////////////////////////////////////

/* ++++ Project 3.2 for swapping ++++ */
void 
swap_init(void)
{
    block_swap = block_get_role(BLOCK_SWAP);
    if(block_swap == NULL)
        return;
    swap_map = bitmap_create(block_size(block_swap)/SECTOR_SIZE);
    bitmap_set_all(swap_map, 1);
    //lock_init(&swap_lock);
}



void
swap_in(void *kaddr, struct vm_entry *vme)
{
    //lock_acquire(&swap_lock);
    for (int i=0;i<SECTOR_SIZE;i++){
        // used_index와 swap slot에 저장된 data를 논리 주소 kaddr로 복사
        block_read(swap_map, (vme->swap_slot)*SECTOR_SIZE+i, kaddr+i*BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_map, vme->swap_slot, 1);
    //lock_release(&swap_lock);
}


void swap_out(struct page* victim_page)
{
    //lock_acquire(&swap_lock);
    size_t swap_index = bitmap_scan(swap_map,0,1,1);
    for (int i=0;i<SECTOR_SIZE;i++){
        // kaddr 주소가 가리키는 페이지를 swap partition에 기록
        block_write(swap_map, swap_index*SECTOR_SIZE+i, victim_page->kaddr+i*BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_map, swap_index, 0);
    //lock_release(&swap_lock);
    // page를 기록한 swap slot index를 return
    victim_page->vme->swap_slot = swap_index;
}

/* ++++ Project 3.2 for frame swapping ++++ */
void 
lru_list_init (void){
  /* 1.lru list intialize */
  list_init(&lru_list);
  /* 2.lock of lru_list initilize */
  //lock_init(lru_list_lock);
  /* 3. list_elem NULL */
  lru_clock = NULL;
};

/*struct page {
  void *kaddr;
  struct vm_entry *vme; 
  struct thread *thread; 
  struct list_elem lru; 
}*/

// insert user page to end of the LRU list
void 
add_page_to_lru_list(struct page* page){
  list_push_back(&lru_list, &page->lru);
}

// delete user page from LRU list
void 
del_page_from_lru_list(struct page* page){
  list_remove(&page->lru);
}


struct page* 
alloc_page(enum palloc_flags flags, struct vm_entry *vme){
  struct page * page_allocated = malloc(sizeof(struct page));
  // page allocation
  void *kpage = palloc_get_page(flags);
  page_allocated->kaddr = kpage;

  while(page_allocated->kaddr == NULL){
    struct page *victim_page;
    // 1. Select Victim page
    lock_acquire(&filesys_lock);
    victim_page = select_victim(lru_clock);
    lock_release(&filesys_lock);
    // swapping
    if(victim_page->vme->vm_type==VM_ANON)
      swap_out(victim_page);
    // swapping when dirty bit and VM_BIN
    if(pagedir_is_dirty(victim_page->thread->pagedir, victim_page->vme->vaddr)){
      if(victim_page->vme->vm_type == VM_BIN){
        swap_out(victim_page);
        victim_page->vme->vm_type = VM_ANON;
      }

      else if(victim_page->vme->vm_type == VM_FILE){
        lock_acquire(&filesys_lock);
        file_write_at(victim_page->vme->file, victim_page->vme->vaddr, victim_page->vme->read_bytes, victim_page->vme->offset);
        lock_release(&filesys_lock);
      }
    }
    pagedir_clear_page(victim_page->thread->pagedir, victim_page->vme->vaddr);
    page_allocated->kaddr = palloc_get_page(flags);
    victim_page->vme->is_loaded=false;
    free_page(victim_page->kaddr);

  }
  
  // struct page allocation
  // alloc_page = malloc(sizeof(struct page));
  // struct page initialize
  page_allocated->thread = thread_current();
  //page_allocated->kaddr = kpage;
  page_allocated->vme = vme;
  page_allocated->pin = false;
  add_page_to_lru_list(page_allocated);

  return page_allocated;
}

struct 
page* select_victim(struct list_elem *start)
{
  struct list_elem *e = start;
  struct page *victim_page = NULL;
  while(1){
    if(e==NULL)
      e = list_begin(&lru_list);
    void* vaddr = list_entry(e, struct page, lru)->vme->vaddr;
    // if access bit 1 -> 0 reset, but access bit 0 -> page is victim
    if(pagedir_is_accessed(thread_current()->pagedir, vaddr)){
      // return access bit of pte for vpage in pd
      // Set the access bit to accessed in the pte for vpage in pd
      pagedir_set_accessed(thread_current()->pagedir, vaddr, false);
      e = e->next;
      if(e->next == NULL)
        e =list_begin(&lru_list);
    }

    else{
      victim_page = list_entry(e, struct page, lru);
      lru_clock = e->next;
      if(e->next == NULL)
        lru_clock = list_begin(&lru_list);
      return victim_page;
    }
  }
  /*
  for(e)
  */
  return victim_page;
}

// deallocate page about kaddr
void 
free_page(void *kaddr){
  struct list_elem *e;
  struct page *free_page = NULL;
  //lock_acquire(&filesys_lock);
  // find page same kaddr
  for (e=list_begin(&lru_list); e!=list_end(&lru_list); e=list_next(e)){
    free_page = list_entry(e, struct page, lru);
    // same kaddr
    if (free_page->kaddr == kaddr) {
      break;
    }
  }
  // this page free
  del_page_from_lru_list(free_page);
  // 2. memory free
  palloc_free_page(kaddr);
  free(free_page);
}


void set_pin(void *vaddr)
{
  struct list_elem *e;
  struct page *page_pin;

  for(e=list_begin(&lru_list); e!=list_end(&lru_list); e=list_next(e))
  {
    if (list_entry(e, struct page, lru)->vme->vaddr == pg_round_down(vaddr)) 
    {
      page_pin = list_entry(e, struct page, lru);
      page_pin->pin = true;
      break;
    }
  }
}

void unset_pin(void *vaddr)
{
  struct list_elem *e;
  struct page *page_pin;
  for (e=list_begin(&lru_list); e!=list_end(&lru_list);e=list_next(e))
  {
    if (list_entry(e, struct page, lru)->vme->vaddr == pg_round_down(vaddr)) 
    {
      page_pin = list_entry (e, struct page, lru);
      page_pin->pin = false;
      break;
    }
  }
}