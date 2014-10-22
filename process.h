#ifndef PROCESS_H
#define PROCESS_H

#include <stdbool.h>
#include <sys/types.h>

int ARGC;
char **ARGV;

void process_set_name(const char *name);
void process_disable_ptrace(void);
bool process_is_same_executable(pid_t pid);

#endif
