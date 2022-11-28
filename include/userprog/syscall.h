#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <user/syscall.h>

void syscall_init (void);

static struct lock filesys_lock; // for syn read/write

#endif /* userprog/syscall.h */
