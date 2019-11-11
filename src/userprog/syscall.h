#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define ARG_NUM_HALT 0
#define ARG_NUM_EXIT 1
#define ARG_NUM_EXEC 1
#define ARG_NUM_WAIT 1
#define ARG_NUM_CREATE 2
#define ARG_NUM_REMOVE 1
#define ARG_NUM_OPEN 1
#define ARG_NUM_FILESIZE 1
#define ARG_NUM_READ 3
#define ARG_NUM_WRITE 3
#define ARG_NUM_SEEK 2
#define ARG_NUM_TELL 1
#define ARG_NUM_CLOSE 1

#define STATUS_KILLED -1

void syscall_init (void);
struct file_descriptor * file_descriptor_finder (int fd);
#endif /* userprog/syscall.h */
