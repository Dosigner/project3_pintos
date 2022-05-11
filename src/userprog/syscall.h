#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "vm/page.h"

typedef int pid_t;
typedef int mapid_t;

void syscall_init (void);

struct lock filesys_lock;


/* ++++++ process related system calls +++++ */
void halt(void);
void exit(int);
pid_t exec(const char *);
int wait(pid_t);
/* +++++++++++++++++++++++++++++++++++++++++ */



/* ++++++ file related system calls +++++ */
bool create(const char*, unsigned);
bool remove(const char*);
/* +++++ Project2.4 File Descriptor +++++ */
int open(const char*);
int filesize(int);
int read(int, void*, unsigned);
int write(int, const void*, unsigned);
void seek(int, unsigned);
unsigned tell(int);
void close(int);
/* +++++++++++++++++++++++++++++++++++++ */

/* +++++++++++++++++++++++++++++++++ */
/* Project 3 and optionally project 4. */
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t);
struct vm_entry * check_address_vm (void *addr);
void do_munmap(struct mmap_file *mmap_f);
/* +++++++++++++++++++++++++++++++++ */

void check_address(void *esp, bool read_write);
void check_buffer(void *addr, void *esp);
void check_valid_buffer(void *buffer, unsigned size, bool to_write);
void check_valid_string(const void* str);
#endif /* userprog/syscall.h */
