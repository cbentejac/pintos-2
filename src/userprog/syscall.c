#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
int get_file (int fd, struct process_file **p);
bool is_valid_ptr (void *ptr);
bool is_valid_buffer (void *buffer, int size);
struct lock syslock;
void get_args (struct intr_frame *f, int *arg, int n);

void
syscall_init (void) 
{
  lock_init (&syslock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[3];
  
  if (!is_valid_ptr ((void *) f->esp))
    exit (ERROR);

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
      f->eax = create ((const char *) arg[0], (unsigned) arg[1]);
      break;
    }

    case SYS_REMOVE:
    {
      get_args (f, &arg[0], 1);
      f->eax = remove ((const char *) arg[0]);
      break;
    }

    case SYS_OPEN:
    {
      get_args (f, &arg[0], 1);
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
      if (!is_valid_ptr ((void *) arg[1]))
        exit (ERROR);
      f->eax = read (arg[0], (void *) arg[1], (unsigned) arg[2]);
      break;
    }

    case SYS_WRITE:
    {
      get_args (f, &arg[0], 3);
      f->eax = write (arg[0], (void *) arg[1], (unsigned) arg[2]);
      break;
    }

    case SYS_SEEK:
    {
      get_args (f, &arg[0], 2);
      seek (arg[0], (unsigned) arg[1]);
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

/* Terminates Pintos by calling shutdown_power_off() (declared in 
   devices/shutdown.h). This should be seldom used, because you lose 
   some information about possible deadlock situations, etc. */
void
halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. 
   If the process's parent waits for it (see below), this is the status 
   that will be returned. Conventionally, a status of 0 indicates success 
   and nonzero values indicate errors. */
void 
exit (int status)
{
  struct thread *t = thread_current ();
  struct info_thread *info = t->info;
  struct info_thread *tmp;
  struct list_elem *e = list_begin (&info->children_list);  
  struct process_file *free_f;
  
  printf ("%s: exit(%d)\n", t->name, status); 

  while (e != list_end (&info->children_list))
  {
    tmp = list_entry (e, struct info_thread, elem);
    tmp->parent_alive = false;
    if (!tmp->alive)
    {
      e = list_remove (&tmp->elem);
      free (tmp);
    }
    else
      e = list_next (e);
  }

  if (info->parent_alive)
  {
    info->alive = false;
    info->exit = status;
    sema_up (&info->sema_wait);
  }
  else
  {
    list_remove (&info->elem);
    free (info);
  }

  /* Free files. */
  e = list_begin (&t->files_list);
  while (e != list_end (&t->files_list))
  {
    free_f = list_entry (e, struct process_file, elem);
    file_close (free_f->file);
    e = list_remove (&free_f->elem);
    free (free_f);
  }
  
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing any 
   given arguments, and returns the new process's program id (pid). 
   Must return pid -1, which otherwise should not be a valid pid, if 
   the program cannot load or run for any reason. Thus, the parent 
   process cannot return from the exec until it knows whether the child 
   process successfully loaded its executable. */
pid_t
exec (const char *cmd_line)
{
  if (!is_valid_ptr ((void *) cmd_line))
    exit (ERROR);
  pid_t pid = process_execute (cmd_line);
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status.
   If pid is still alive, waits until it terminates. Then, returns the 
   status that pid passed to exit. If pid did not call exit(), but was 
   terminated by the kernel (e.g. killed due to an exception), wait(pid) 
   must return -1. */
int
wait (pid_t pid)
{
  pid_t ret = process_wait (pid);
  return ret;
}

/* Creates a new file called file initially initial_size bytes in size. 
   Returns true if successful, false otherwise. Creating a new file 
   does not open it: opening the new file is a separate operation 
   which would require a open system call. */
bool
create (const char *file, unsigned initial_size)
{
  int ret;
  if (file == NULL)
    exit (ERROR);

  if (!is_valid_ptr ((void *) file))
    exit (ERROR);

  lock_acquire (&syslock);
  ret = filesys_create (file, initial_size);
  lock_release (&syslock);
  return ret;
}

/* Deletes the file called file. Returns true if successful, false 
   otherwise. A file may be removed regardless of whether it is open 
   or closed, and removing an open file does not close it. */
bool
remove (const char *file)
{
  bool ret;
   
  lock_acquire (&syslock);
  ret = filesys_remove (file);
  lock_release (&syslock);

  return ret; 
}

/* Opens the file called file. Returns a nonnegative integer handle 
   called a "file descriptor" (fd), or -1 if the file could not be opened.
   File descriptors numbered 0 and 1 are reserved for the console: 
   fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is 
   standard output. The open system call will never return either of 
   these file descriptors, which are valid as system call arguments only 
   as explicitly described below. */
int
open (const char *file)
{
  struct thread *t = thread_current ();
  struct process_file *pf = (struct process_file *) malloc
                            (sizeof (struct process_file));

  if (!is_valid_ptr ((void *) file))
    exit (ERROR);

  if (file == NULL)
  { 
    free (pf);
    return ERROR;
  }

  lock_acquire (&syslock);
  pf->file = filesys_open (file);
  lock_release (&syslock);

  if (pf->file == NULL)
  {
    free (pf);
    return ERROR;
  }

  pf->fd = (t->fd)++;

  list_push_back (&t->files_list, &pf->elem);
  return pf->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd)
{
  struct process_file *pf;
  
  if (get_file (fd, &pf) < 0)
    return ERROR;
  return file_length (pf->file);
}

/* Reads size bytes from the file open as fd into buffer. Returns the 
   number of bytes actually read (0 at end of file), or -1 if the file 
   could not be read (due to a condition other than end of file). Fd 0 
   reads from the keyboard using input_getc(). */
int
read (int fd, void *buffer, unsigned size)
{
  struct process_file *pf;
  unsigned i;
  uint8_t *local_buffer = (uint8_t *) buffer;

  if (buffer == NULL)
    return ERROR;

  if (!is_valid_buffer (buffer, size))
    return ERROR;

  if (fd == STDIN)
  {
    for (i = 0; i < size; i++)
      local_buffer[i] = input_getc (); 
    return size;
  }
 
  else if (fd == STDOUT)
    return ERROR;

  if (get_file (fd, &pf))
    return ERROR;

  lock_acquire (&syslock);
  size = file_read (pf->file, buffer, size);
  lock_release (&syslock);
  return size;
}

/* Writes size bytes from buffer to the open file fd. Returns the 
   number of bytes actually written, which may be less than size if some 
   bytes could not be written. */
int
write (int fd, const void *buffer, unsigned size)
{ 
  struct process_file *pf;

  if (buffer == NULL)
    return ERROR;

  if (!is_valid_buffer ((void *) buffer, size))
    exit (ERROR);

  if (fd == STDOUT)
  {
    putbuf ((char *) buffer, size);
    return size;
  }
  
  else if (fd == STDIN)
    return ERROR;

  if (get_file (fd, &pf) < 0)
    return ERROR;

  lock_acquire (&syslock);
  size = file_write (pf->file, buffer, size);
  lock_release (&syslock);
  return size;
}

/* Changes the next byte to be read or written in open file fd to 
   position, expressed in bytes from the beginning of the file. 
   (Thus, a position of 0 is the file's start.) */
void
seek (int fd, unsigned position)
{
  struct process_file *pf;
  if (!get_file (fd, &pf))
  {
    lock_acquire (&syslock);
    file_seek (pf->file, position);
    lock_release (&syslock);
  }
}

/* Returns the position of the next byte to be read or written in 
   open file fd, expressed in bytes from the beginning of the file. */
unsigned 
tell (int fd)
{
  int position = ERROR;
  struct process_file *pf;

  if (!get_file (fd, &pf))
    position = file_tell (pf->file);

  return position;
}

/* Closes file descriptor fd. Exiting or terminating a process 
   implicitly closes all its open file descriptors, as if by calling 
   this function for each one. */
void
close (int fd)
{
  struct process_file *pf;

  if (get_file (fd, &pf) == SUCCESS)
  {
    lock_acquire (&syslock);
    file_close (pf->file);
    lock_release (&syslock);
    list_remove (&pf->elem);
    free (pf);
  }
}

/* Finds the file in the current thread's open files files_list 
   that has a file descriptor equal to FD. If such a file exists,
   associates its process_file structure to P and returns SUCCESS.
   If not, returns ERROR.
 */
int
get_file (int fd, struct process_file **p)
{
  struct thread *t = thread_current ();
  struct list_elem *e = list_begin (&t->files_list);
  struct process_file *pf;  

  while (e != list_end (&t->files_list))
  {
    pf = list_entry (e, struct process_file, elem);
    if (pf->fd == fd)
    {
      *p = pf;
      return SUCCESS;
    }
    e = list_next (e);
  }
  return ERROR;
}

/* Returns true if the pointer PTR is in user space and is mapped
   to a page. If one of those conditions is not satisfied, returns
   false. */
bool
is_valid_ptr (void *ptr)
{
  if (!is_user_vaddr (ptr))
    return false;

  if (pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
    return false;

  return true;
}

/* Returns true if the buffer BUFFER is in user space and mapped
   to a page. If one of those conditions is not satisfied, returns
   false. */
bool
is_valid_buffer (void *buffer, int size)
{
  int i;
  void *tmp = buffer;
  uint32_t *pagedir = thread_current ()->pagedir;
  for (i = 0; i < size - 1; i++)
  {
    tmp++;
    if (!is_valid_ptr (tmp))
      return false;
    if (pagedir_get_page (pagedir, tmp) == NULL)
      return false;
  }
  return true;
}

/* Gets the arguments from the stack and saves them into the array ARG. */
void
get_args (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
 
  for (i = 0; i < n; i++)
  {
    ptr = (int *) f->esp + i + 1; /* Get the argument. */
    if (!is_valid_ptr ((void *) ptr)) /* Check if it is a valid address. */
      exit (ERROR); /* If not, exit with an error. */
    arg[i] = *ptr;  
  }
}
