#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"



tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* ++++ 2.1 Argument Passing ++++ */
void argument_stack(char* argv[], int argc, void **esp);
/* ++++++++++++++++++++++++++++++ */

/* +++++ 3.1 Virtual Memory ++++ */
bool handle_mm_fault(struct vm_entry *vme);
/* ++++++++++++++++++++++++++++++ */

/* ++++ 3.2 mmap ++++ */
struct file * process_get_file(int fd);
#endif /* userprog/process.h */
