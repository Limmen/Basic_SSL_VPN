#include "util.h"
#include "common.h"
#define PORT 55555

struct input_opts {
    char remote_ip[16];
    int cliserv;
    char if_name[IFNAMSIZ];
    int flags;
    int port;
};

void usage(char *progname);
struct input_opts parse_input(int argc, char *argv[]);
