#include <stdarg.h>
#include <stdio.h>

#define CLIENT 0
#define SERVER 1

extern int debug;

void do_debug(char *msg, ...);
void my_err(char *msg, ...);