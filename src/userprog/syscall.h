#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

struct child_process
{
  int pid;
  int load_status;
  bool wait;
  bool exit;
  int status;
  struct lock lock_wait;
  struct list_elem elem;
};

/* Lock to avoid race conditions during the file system calls. */
struct lock sys_lock;

struct process_file
{
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct child_process *add_child_process (int pid);
struct child_process *get_child_process (int pid);
void remove_child_process (struct child_process *cp);
void remove_child_processes (void);
void syscall_init (void);
void is_valid_ptr (const void *vaddr);
int user_to_kernel_ptr (const void *vaddr);
struct file *get_file (int fd);
void close_file (int fd);
#endif /* userprog/syscall.h */
