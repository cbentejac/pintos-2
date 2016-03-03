#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>
#include <user/syscall.h>
#include "threads/synch.h"

#define SUCCESS 0
#define ERROR -1
#define STDIN 0
#define STDOUT 1

void syscall_init (void);

/* Syscall implementation. */
void exit (int);
int write (int, const void *, unsigned);
int read (int, void *, unsigned);
int open (const char *);
void close (int);
int wait (pid_t);
void halt (void);
pid_t exec (const char *);
bool create (const char *, unsigned);
bool remove (const char *);
int filesize (int);
void seek (int, unsigned);
unsigned tell (int);

#endif /* userprog/syscall.h */
