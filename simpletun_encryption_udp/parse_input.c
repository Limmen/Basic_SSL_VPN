#include "parse_input.h"

int debug;

/**
 * Simple function to inform user about valid options
 *
 * @param progname
 */
void usage(char *progname) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr,
            "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr,
            "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}

/**
 * Function to parse input arguments
 *
 * @param argc number of arguments
 * @param argv command-line args
 * @return struct input_opts with parsed input
 */
struct input_opts parse_input(int argc, char *argv[]) {
    struct input_opts input;
    input.flags = IFF_TUN;
    strncpy(input.if_name, "", IFNAMSIZ-1);
    strncpy(input.remote_ip, "", 15);
    input.port = PORT;
    input.cliserv = -1;

    unsigned short int port = PORT;



    int header_len = IP_HDR_LEN;
    int option;
    char *progname = argv[0];
    /* Check command line options getopt function goes through the command line args with preceeding "-" or "--" */
    while ((option = getopt(argc, argv, "i:p:r:scuahd")) > 0) {
        switch (option) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                usage(progname);
                break;
            case 'i':
                strncpy(input.if_name, optarg,
                        IFNAMSIZ - 1); //copies IFNAMSIZ-1 number of bytes from optarg to if_name buffer
                break;
            case 's':
                input.cliserv = SERVER;
                break;
            case 'c':
                input.cliserv = CLIENT;
                break;
            case 'r':
                strncpy(input.remote_ip, optarg, 15);
                break;
            case 'p':
                input.port = atoi(optarg); //converts string optarg into integer
                break;
            case 'u':
                input.flags = IFF_TUN;
                break;
            case 'a':
                input.flags = IFF_TAP;
                header_len = ETH_HDR_LEN;
                break;
            default:
                my_err("Unknown option %c\n", option);
                usage(progname);
        }
    }
    /* optind is the index of the next element to be processed in argv */

    argv += optind;
    argc -= optind;

    if (argc > 0) {
        my_err("Too many options!\n");
        usage(progname);
    }
    if (input.if_name == '\0') {
        my_err("Must specify interface name!\n");
        usage(progname);
    } else if (input.cliserv < 0) {
        my_err("Must specify client or server mode!\n");
        usage(progname);
    } else if ((input.cliserv == CLIENT) && (input.remote_ip == '\0')) {
        my_err("Must specify server address!\n");
        usage(progname);
    }
    return input;
}