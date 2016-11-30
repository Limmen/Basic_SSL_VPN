/**
 * derived from simpletun.c, to changed to use UDP instead of TCP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

    struct ifreq ifr; //struct for a netdevice
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr)); //initialize netdevice to 0's

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ); //copies dev to ifr_name
    }

    /**
     * ioctl call to create the virtual interface
     */
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n) {

    int nread;

    if ((nread = read(fd, buf, n)) < 0) {
        perror("Reading data");
        exit(1);
    }
    return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n) {

    int nwrite;

    if ((nwrite = write(fd, buf, n)) < 0) {
        perror("Writing data");
        exit(1);
    }
    return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

    int nread, left = n;

    while (left > 0) {
        if ((nread = cread(fd, buf, left)) == 0) {
            return 0;
        } else {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...) {

    va_list argp;

    if (debug) {
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
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

int main(int argc, char *argv[]) {

    int tap_fd, option; //tap_fd will be either referring to a TAP or TUN interface, depending on user parameters
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int header_len = IP_HDR_LEN;
    int maxfd;
    uint16_t nread, nwrite, plength;
    char buffer[BUFSIZE];
    struct sockaddr_in local_socket_info, remote_socket_info;
    char remote_ip[16] = "";
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1;    /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;

    progname = argv[0];

    /* Check command line options getopt function goes through the command line args with preceeding "-" or "--" */
    while ((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
        switch (option) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                usage();
                break;
            case 'i':
                strncpy(if_name, optarg,
                        IFNAMSIZ - 1); //copies IFNAMSIZ-1 number of bytes from optarg to if_name buffer
                break;
            case 's':
                cliserv = SERVER;
                break;
            case 'c':
                cliserv = CLIENT;
                strncpy(remote_ip, optarg, 15);
                break;
            case 'p':
                port = atoi(optarg); //converts string optarg into integer
                break;
            case 'u':
                flags = IFF_TUN;
                break;
            case 'a':
                flags = IFF_TAP;
                header_len = ETH_HDR_LEN;
                break;
            default:
                my_err("Unknown option %c\n", option);
                usage();
        }
    }

    /* optind is the index of the next element to be processed in argv */
    argv += optind;
    argc -= optind;

    if (argc > 0) {
        my_err("Too many options!\n");
        usage();
    }

    if (*if_name == '\0') {
        my_err("Must specify interface name!\n");
        usage();
    } else if (cliserv < 0) {
        my_err("Must specify client or server mode!\n");
        usage();
    } else if ((cliserv == CLIENT) && (*remote_ip == '\0')) {
        my_err("Must specify server address!\n");
        usage();
    }

    //Done with arguments-parsing

    /* initialize tun/tap interface */
    if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }

    do_debug("Successfully connected to interface %s\n", if_name);

    /**
     * Creates UDP socket for communication.
     * AF_INET = IPv4
     * SOCK_DGRAM = UDP datagram socket
     */
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        exit(1);
    }

    /**
     * prepare local address of the socket
     */
    memset(&local_socket_info, 0,
           sizeof(local_socket_info)); //copies sizeof(local_socket_info) number of 0's to &local_socket_info
    local_socket_info.sin_family = AF_INET;
    local_socket_info.sin_addr.s_addr = htonl(INADDR_ANY);
    local_socket_info.sin_port = htons(port);

    /**
     * prepare remote address of the socket
     */
    memset(&remote_socket_info, 0, sizeof(remote_socket_info));
    remote_socket_info.sin_family = AF_INET;
    remote_socket_info.sin_addr.s_addr = inet_addr(remote_ip);
    remote_socket_info.sin_port = htons(port);

    /* When created, the socket have no address, here we assign address pointed to by local_socket_info to socket
     * pointed to by filedescriptor sock_fd
     */
    if (bind(sock_fd, (struct sockaddr *) &local_socket_info, sizeof(local_socket_info)) < 0) {
        perror("bind()");
        exit(1);
    }

    /**
     * Connect udp socket to remote, note that since UDP is connectionless this simply configures the socket to send
     * data by default to the remote address and to only receive from that address, no connection is established.
     */
    if (connect(sock_fd, (struct sockaddr *) &remote_socket_info, sizeof(remote_socket_info)) < 0) {
        perror("connect()");
        exit(1);
    }

    net_fd = sock_fd;

    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

    while (1) {
        int ret;
        fd_set rd_set; //file descriptor set

        FD_ZERO(&rd_set); //FD_ZERO is a macro that clears the fd-set
        FD_SET(tap_fd, &rd_set); //Adds fd tap_fd to the set
        FD_SET(net_fd, &rd_set); //Adds net_fd to the set

        /**
         * Monitors filedescriptors to know when they are ready for I/O, uses no timeout (NULL), first argument is
         * the highest-numbered file-descriptor in any of the sets + 1.
         */
        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        /**
         * -1 is returned on error, EINTR = Interuppted function call
         */
        if (ret < 0 && errno == EINTR) {
            continue;
        }

        if (ret < 0) {
            perror("select()");
            exit(1);
        }

        /**
         * ret is the number of fd's that are ready for IO, and rd_set now contain those fd's,
         * data could be from either tap_fd, net_fd or both.
         *
         * If data comes from tap_fd this program just works like a middlelayer between the application writing to
         * tap/tun and the network layer, we will simply forward the data to the tunnel (socket net_fd)
         *
         * If data comes from net_fd this program simply forwards it to the TUN/TAP interface which will put the data
         * into the OS network stack as data direct from the wire, and will eventually be delivered to the application.
         */
        if (FD_ISSET(tap_fd, &rd_set)) {
            /* data from tun/tap: just read it and write it to the network */
            nread = cread(tap_fd, buffer, BUFSIZE);

            tap2net++;
            do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

            /* write length + packet */
            plength = htons(nread);
            nwrite = cwrite(net_fd, (char *) &plength, sizeof(plength));
            nwrite = cwrite(net_fd, buffer, nread);

            do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
        }

        if (FD_ISSET(net_fd, &rd_set)) {
            /* data from the network: read it, and write it to the tun/tap interface.
             * We need to read the length first, and then the packet */

            /* Read length */
            nread = read_n(net_fd, (char *) &plength, sizeof(plength));
            if (nread == 0) {
                /* ctrl-c at the other end */
                break;
            }

            net2tap++;

            /* read packet */
            nread = read_n(net_fd, buffer, ntohs(plength));
            do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

            /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
            nwrite = cwrite(tap_fd, buffer, nread);
            do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
        }
    }
    return (0);
}
