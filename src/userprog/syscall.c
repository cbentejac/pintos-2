#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"


static void syscall_handler (struct intr_frame *);
int add_file (struct file *f);
void get_args (struct intr_frame *f, int *arg, int n);

void
syscall_init (void) 
{
  lock_init (&sys_lock); /* Initializes the lock. */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  is_valid_ptr ((const void *) f->esp);
  int arg[3];

 
  switch (*(int *) f->esp)
  {
    case SYS_HALT:
    {
      halt ();
      break;
    }
    
    case SYS_EXIT:
    {
      get_args (f, &arg[0], 1);
      exit (arg[0]);
      break;
    }

    case SYS_EXEC:
    {
      get_args (f, &arg[0], 1);
      arg[0] = user_to_kernel_ptr ((const void *) arg[0]);
      f->eax = exec ((const char *) arg[0]);
      break;
    }

    case SYS_WAIT:
    {
      get_args (f, &arg[0], 1);
      f->eax = wait (arg[0]);
      break;
    }

    case SYS_CREATE:
    { 
      get_args (f, &arg[0], 2);
      arg[0] = user_to_kernel_ptr ((const void *) arg[0]);
      f->eax = create ((const char *) arg[0], (unsigned) arg[1]);
      break;
    }

    case SYS_REMOVE:
    {
      get_args (f, &arg[0], 1);
      arg[0] = user_to_kernel_ptr ((const void *) arg[0]);
      f->eax = remove ((const char *) arg[0]);
      break;
    }

    case SYS_OPEN:
    {
      get_args (f, &arg[0], 1);
      arg[0] = user_to_kernel_ptr ((const void *) arg[0]);
      f->eax = open ((const char *) arg[0]);
      break;
    }
  
    case SYS_FILESIZE:
    {
      get_args (f, &arg[0], 1);
      f->eax = filesize (arg[0]);
      break;
    }

    case SYS_READ:
    {
      get_args (f, &arg[0], 3);
      arg[1] = user_to_kernel_ptr ((const void *) arg[1]);
      f->eax = read (arg[0], (void *) arg[1], (unsigned) arg[2]);
      break;
    }

    case SYS_WRITE:
    {
      get_args (f, &arg[0], 3);
      arg[1] = user_to_kernel_ptr ((const void *) arg[1]);
      f-> eax = write (arg[0], (const void *) arg[1], (unsigned) arg[2]);
      break;
    }

    case SYS_SEEK:
    {
      get_args (f, &arg[0], 2);
      seek (arg[0], (unsigned) arg[1]); // Void value, so no f->eax.
      break;
    }

    case SYS_TELL:
    {
      get_args (f, &arg[0], 1);
      f->eax = tell (arg[0]);
      break;
    }

    case SYS_CLOSE:
    {
      get_args (f, &arg[0], 1);
      close (arg[0]);
      break;
    }
  }
}

/* The descriptions of functions halt, exit, exec, wait, create, remove,
   open, filesize, read, write, seek, tell and close are taken from
   Project 2's webpage. */

/* Terminates Pintos. */
void
halt (void)
{ 
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to 
   the kernel. If the process's parent waits for it, this is 
   the status that will be returned. Conventionally, a status 
   of 0 indicates success and nonzero values indicate errors. */
void 
exit (int status)
{
  if (thread_alive (thread_current ()->parent))
    thread_current ()->cp->status = status;

  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing 
   any given arguments, and returns the new process's program id 
   (pid). Must return pid -1, which otherwise should not be a valid 
   pid, if the program cannot load or run for any reason. Thus, 
   the parent process cannot return from the exec until it knows 
   whether the child process successfully loaded its executable. */
pid_t
exec (const char *cmd_line)
{
  pid_t pid = process_execute (cmd_line);
  struct child_process *cp = get_child_process (pid);

  if (cp == NULL)
    return -1; 

  while (cp->load_status == 0) // 0 = not loaded.
  {
    // busy waiting
    barrier (); /* Re-checks condition. */
  }
  if (cp->load_status == -1) // -1 = load fail.
    return -1;

  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status.
   If pid is still alive, waits until it terminates. Then, returns 
   the status that pid passed to exit. If pid did not call exit(), 
   but was terminated by the kernel (e.g. killed due to an exception), 
   wait(pid) must return -1. */
int 
wait (pid_t pid)
{
  return process_wait (pid);
}

/* From this point, we enter file system calls.
   To protect the files from race conditions, we use a lock. */

/* Creates a new file called file initially initial_size bytes 
   in size. Returns true if successful, false otherwise. */
bool
create (const char *file, unsigned initial_size)
{
  lock_acquire (&sys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&sys_lock);
  return success;
}

/* Deletes the file called file. Returns true if successful, 
   false otherwise. A file may be removed regardless of whether 
   it is open or closed, and removing an open file does not close it. */
bool
remove (const char *file)
{
  lock_acquire (&sys_lock);
  bool success = filesys_remove (file);
  lock_release (&sys_lock);
  return success;
}

/* Opens the file called file. Returns a nonnegative integer 
   handle called a "file descriptor" (fd), or -1 if the file could 
   not be opened. */
int
open (const char *file)
{
  lock_acquire (&sys_lock);
  struct file *f = filesys_open (file);
  int fd;

  if (f != NULL) // If the file we are trying to open exists. 
    fd = add_file (f);
  else
    fd = -1; // The file does not exist: error. 

  lock_release (&sys_lock);
  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd)
{
  lock_acquire (&sys_lock);
  int size;
  struct file *f = get_file (fd);

  if (f != NULL)
    size = file_length (f);
  else
    size = -1; 
  
  lock_release (&sys_lock);
  return size;
}

/* Reads size bytes from the file open as fd into buffer. Returns
   the number of bytes actually read (0 at end of file), or -1 if
   the file could not be read (due to a condition other than end 
   of file). */
int 
read (int fd, void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
  {
    unsigned i;
    uint8_t *local_buffer = (uint8_t *) buffer;
    for (i = 0; i < size; i++)
    {
      local_buffer[i] = input_getc ();
    }
    return size;
  }
  
  lock_acquire (&sys_lock);
  struct file *f = get_file (fd);
  int b;
  
  if (f != NULL)
    b = file_read (f, buffer, size);
  else
    b = -1;

  lock_release (&sys_lock);
  return b;
}

/* Writes size bytes from buffer to the open file fd. Returns the 
   number of bytes actually written, which may be less than size
   if some bytes could not be written. */
int
write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, size);
    return size;
  }

  lock_acquire (&sys_lock);
  struct file *f = get_file (fd);
  int b;
  
  if (f != NULL)
    b = file_write (f, buffer, size);
  else
    b = -1;

  lock_release (&sys_lock);
  return b;
}

/* Changes the next byte to be read or written in open file fd 
   to position, expressed in bytes from the beginning of the file. 
  (Thus, a position of 0 is the file's start.) */
void
seek (int fd, unsigned position)
{
  lock_acquire (&sys_lock);
  struct file *f = get_file (fd);
  if (f != NULL)
    file_seek (f, position);
  lock_release (&sys_lock);
}

/* Returns the position of the next byte to be read or written in 
   open file fd, expressed in bytes from the beginning of the file. */
unsigned
tell (int fd)
{
  lock_acquire (&sys_lock);
  struct file *f = get_file (fd);
  off_t offset;
  if (f != NULL)
    offset = file_tell (f);
  else
    offset = -1;

  lock_release (&sys_lock);
  return offset;
}

/* Closes file descriptor fd. Exiting or terminating a process 
   implicitly closes all its open file descriptors, as if by calling 
   this function for each one. */
void
close (int fd)
{
  lock_acquire (&sys_lock);
  close_file (fd);
  lock_release (&sys_lock);
}

/* Checks whether the virtual address VADDR is a user virtual address
   and is not situated before the beginning of the code segment. If 
   one of this condition is not satisfied, call exit. */
void
is_valid_ptr (const void *vaddr)
{
  if (is_user_vaddr (vaddr) == false || vaddr < ((void *) 0x08048000))
    exit (-1);
}

/* Converts a user virtual address to a kernel virtual address. */
int user_to_kernel_ptr (const void *vaddr)
{
  is_valid_ptr (vaddr);
  void *ptr = pagedir_get_page (thread_current ()->pagedir, vaddr);

  if (ptr == NULL)
  {
    exit (-1);
  }
  return (int) ptr;
}

int 
add_file (struct file *f)
{
  /* Allocate memory for a new file to ass to the list. */
  struct process_file *pf = malloc (sizeof (struct process_file));
  pf->file = f;
  pf->fd = thread_current ()->fd;
  /* Increments the file descriptor. */
  thread_current ()->fd = thread_current ()->fd + 1; 
  list_push_back (&thread_current ()->file_list, &pf->elem);
  return pf->fd;
}

struct file *
get_file (int fd)
{
  struct list_elem *e = list_begin (&thread_current ()->file_list);

  /* Iterates through the file list until the file corresponding
     to the file descriptor given in parameter is found or until
     all the list elements have been checked. */
  while (e != list_end (&thread_current ()->file_list))
  {
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (pf->fd == fd)
      return pf->file;
    e = list_next (e);
  }
  return NULL; // If the file has not been found, return NULL.
}

void 
close_file (int fd)
{
  struct list_elem *e = list_begin (&thread_current ()->file_list);
  /* Used to iterate through the next element if e is removed. */
  struct list_elem *next; 

  while (e != list_end (&thread_current ()->file_list))
  {
    struct process_file *pf = list_entry (e, struct process_file, elem);
    next = list_next (e); // In case e would be removed right after.
    
    /* fd = -1 means that we want to close all the files (in case of 
       an exit, for example). */
    if (pf->fd == fd || fd == -1)
    {
      file_close (pf->file);
      list_remove (&pf->elem);
      /* Free the memory that had been allocated during add_file. */
      free (pf);

      /* If we don't want to close all the files (fd != -1), we don't 
         need to keep on iterating through the list, as we have just 
         closed the file we wanted to close. We can break at this point. */       if (fd != -1)
        break;
    }
    e = next;
  }
}


struct child_process *
add_child_process (int pid)
{
  struct child_process *cp = malloc (sizeof (struct child_process));
  cp->pid = pid;
  cp->load_status = 0;
  cp->wait = false;
  cp->exit = false;
  lock_init (&cp->lock_wait);
  list_push_back (&thread_current ()->children_list, &cp->elem);
  return cp;
}

struct child_process *
get_child_process (int pid)
{
  struct list_elem *e = list_begin (&thread_current ()->children_list);
  while (e != list_end (&thread_current ()->children_list))
  {
    struct child_process *cp = list_entry (e, struct child_process, elem);
    if (pid == cp->pid)
      return cp;
    e = list_next (e);
  }
  return NULL;
}


void
remove_child_process (struct child_process *cp)
{
  list_remove (&cp->elem);
  free (cp);
}

void 
remove_child_processes (void)
{
  struct list_elem *e = list_begin (&thread_current ()->children_list);
  struct list_elem *next;

  while (e != list_end (&thread_current ()->children_list))
  {
    next = list_next (e);
    struct child_process *cp = list_entry (e, struct child_process, elem);
    list_remove (&cp->elem);
    free (cp);
    e = next;
  }
}

/* Gets argument from the stack. */
void
get_args (struct intr_frame *f, int *arg, int n)
{
  int i; 
  int *ptr;
  for (i = 0; i < n; i++)
  {
    ptr = (int *) f->esp + i + 1;
    is_valid_ptr ((const void *) ptr);
    arg[i] = *ptr;
  }
}
