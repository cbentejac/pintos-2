#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"


/* Lock to avoid race conditions during the file system calls. */
struct lock sys_lock;

struct process_file
{
  struct file *file;
  int fd;
  struct list_elem elem;
};

void syscall_init (void);
void is_valid_ptr (const void *vaddr);
int user_to_kernel_ptr (const void *vaddr);
struct file *get_file (int fd);
void close_file (int fd);
#endif /* userprog/syscall.h */
