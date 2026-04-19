#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>

typedef int pid_t;
typedef int off_t;

void syscall_init (void);
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

#define READDIR_MAX_LEN 14

bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);
int symlink (const char* target, const char* linkpath);

static struct lock filesys_lock; // for syn read/write

#endif /* userprog/syscall.h */
