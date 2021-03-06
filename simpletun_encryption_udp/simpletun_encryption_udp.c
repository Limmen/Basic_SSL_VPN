/**
 * simpletun_udp.c derived from simpletun.c (see simpletun.c for LICENSE, credit etc), to changed to use UDP instead of TCP
 */

#include "simpletun_encryption_udp.h"
/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 4000

int main(int argc, char *argv[]) {
    int tap_fd; //tap_fd will be either referring to a TAP or TUN interface, depending on user parameters
    int maxfd;
    uint16_t nread, nwrite, plength;
    unsigned char buffer[BUFSIZE];
    struct sockaddr_in local_socket_info, remote_socket_info;
    int sock_fd, net_fd;
    unsigned long int tap2net = 0, net2tap = 0;
    struct input_opts input;
    int keysInitialized = 0;

    /* 256 bit key */
    unsigned char key[32];

    /* 128 bit IV */
    unsigned char iv[16];

    /* 256 bit MAC */
    unsigned char *mac;

    /**
     * Initialize SSL libraries
     */
    initializeSSL();

    /**
     * Parse input flags/params
     */
    input = parse_input(argc, argv);

    /* initialize tun/tap interface */
    if ((tap_fd = tun_alloc(input.if_name, input.flags | IFF_NO_PI)) < 0) {
        my_err("Error connecting to tun/tap interface %s!\n", input.if_name);
        exit(1);
    }

    do_debug("Successfully connected to interface %s\n", input.if_name);

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
    local_socket_info.sin_port = htons(input.port);

    /**
     * prepare remote address of the socket
     */
    memset(&remote_socket_info, 0, sizeof(remote_socket_info));
    remote_socket_info.sin_family = AF_INET;
    remote_socket_info.sin_addr.s_addr = inet_addr(input.remote_ip);
    remote_socket_info.sin_port = htons(input.port);

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
    /**
     * Fork process to create secure channel for key exchange
     */
    int pipefd[2];
    pid_t ppid = getpid();
    pid_t cpid;
    pipe(pipefd); // create the pipe
    cpid = fork();
    if (input.cliserv == CLIENT) {
        if (cpid == 0) {
            int r = prctl(PR_SET_PDEATHSIG, SIGTERM);
            if (r == -1) { perror(0); exit(1); }
            client_secure_channel(pipefd, ppid);
        }
    }
    if (input.cliserv == SERVER) {
        if (cpid == 0) {
            server_secure_channel(pipefd, ppid);
            int r = prctl(PR_SET_PDEATHSIG, SIGTERM);
            if (r == -1) { perror(0); exit(1); }
        }
    }
    close(pipefd[1]); //close write-end of pipe
    maxfd = (pipefd[0] > maxfd) ? pipefd[0] : maxfd;
    int pipeClosed = 1;
    /**
     * Read data from TUN interface, Network Interface and Process handling secure channel
     */
    while (1) {
        unsigned char buf[2000];
        int ret;
        fd_set rd_set; //file descriptor set

        FD_ZERO(&rd_set); //FD_ZERO is a macro that clears the fd-set
        FD_SET(tap_fd, &rd_set); //Adds fd tap_fd to the set
        FD_SET(net_fd, &rd_set); //Adds net_fd to the set
        if (pipeClosed != 0) {
            FD_SET(pipefd[0], &rd_set);
        }

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

        int decryptedtext_len, ciphertext_len;

        /**
         * ret is the number of fd's that are ready for IO, and rd_set now contain those fd's,
         * data could be from either tap_fd, net_fd or both.
         *
         * If data comes from tap_fd this program just works like a middlelayer between the application writing to
         * tap/tun and the network layer, we will simply forward the data to the tunnel (socket net_fd)
         *
         * If data comes from net_fd this program simply forwards it to the TUN/TAP interface which will put the data
         * into the OS network stack as data direct from the wire, and will eventually be delivered to the application.
         *
         * If data comes from pipefd[0] (read-end of pipe to secure channel), the privKey + IV will be updated
         */
        if (FD_ISSET(tap_fd, &rd_set)) {
            /* data from tun/tap: just read it and write it to the network */
            nread = cread(tap_fd, buffer, BUFSIZE);
            tap2net++;
            do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

            if (keysInitialized) {
                do_debug("Key and IV is set, encrypting tunnel output \n");

                /* Show the plaintext */
                //do_debug("plaintext is:%s\n", buffer);

                /* Buffer for ciphertext. Ensure the buffer is long enough for the
                 * ciphertext which may be longer than the plaintext, dependant on the
                 * algorithm and mode
                 */
                unsigned char ciphertext[BUFSIZE];

                /* Encrypt the plaintext */
                ciphertext_len = encrypt(buffer, nread, key, iv,
                                         ciphertext);

                /* Show the encrypted text */
                //do_debug("Encrypted text is:%s\n", ciphertext);

                /**
                 * Generate MAC and prepend it to the ciphertext before sending it on the wire
                 */
                mac = addMAC(key, 32, ciphertext, ciphertext_len);
                int msg_len = 32 + ciphertext_len;
                unsigned char msg[msg_len];
                int i;
                for (i = 0; i < 32; i++) {
                    msg[i] = mac[i];
                }
                int j = 0;
                for (i = 32; i < msg_len; i++) {
                    msg[i] = ciphertext[j];
                    j++;
                }
                /* write length + packet */
                plength = htons(msg_len);
                nwrite = cwrite(net_fd, (char *) &plength, sizeof(plength));
                nwrite = cwrite(net_fd, msg, msg_len);
            } else {
                do_debug("Key and IV is not setup, all messages on tunnel will be in plaintext");
                /* write length + packet */
                plength = htons(nread);
                nwrite = cwrite(net_fd, (char *) &plength, sizeof(plength));
                nwrite = cwrite(net_fd, buffer, nread);
            }
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
            if (keysInitialized) {
                int i;
                /**
                 * If read more than 32 bytes we expect first 32 bytes to be MAC which need to be verified.
                 */
                if (nread > 32) {
                    unsigned char mac_sign[32];
                    memset(mac_sign, '\0', 32);
                    int msg_len = nread - 32;
                    unsigned char msg[nread - 32];
                    memset(msg, '\0', sizeof(msg_len));
                    for (i = 0; i < 32; i++) {
                        mac_sign[i] = buffer[i];
                    }
                    int j = 0;
                    for (i = 32; i < nread; i++) {
                        msg[j] = buffer[i];
                        j++;
                    }
                    unsigned char *mac_verify = addMAC(key, 32, msg, msg_len);
                    int fail = 0;
                    for (int i = 0; i < 32; i++) {
                        if (*(mac_verify + i) != mac_sign[i])
                        {
                            fail = 1;
                            break;
                        }
                    }
                    if (!fail) {
                        do_debug("MAC is verified \n");
                        /* Buffer for the decrypted text */
                        unsigned char decryptedtext[BUFSIZE];
                        /* Decrypt the ciphertext */
                        decryptedtext_len = decrypt(msg, msg_len, key, iv, decryptedtext);
                        /* Show the decrypted text */
                        //do_debug("Decrypted text is:%s\n", decryptedtext);
                        /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
                        nwrite = cwrite(tap_fd, decryptedtext, decryptedtext_len);
                    } else {
                        do_debug("MAC's does not match, cannot verify that message was not tampered with\n");
                        //nwrite = cwrite(tap_fd, buffer, nread);
                    }
                } else {
                    /* Buffer for the decrypted text */
                    unsigned char decryptedtext[BUFSIZE];
                    /* Decrypt the ciphertext */
                    decryptedtext_len = decrypt(buffer, nread, key, iv, decryptedtext);
                    /* Show the decrypted text */
                    //do_debug("Decrypted text is:%s\n", decryptedtext);
                    /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
                    nwrite = cwrite(tap_fd, decryptedtext, decryptedtext_len);
                }
            } else {
                /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
                nwrite = cwrite(tap_fd, buffer, nread);
            }
            do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
        }
        if (FD_ISSET(pipefd[0], &rd_set)) {
            //memset(buf, '\0', sizeof(buf));
            int n;
            n = read(pipefd[0], buf, 48);
            if (n == 0) {
                do_debug("Pipe to secure TCP channel closed, closing the UPD tunnel as well \n");
                pipeClosed = 0;
                close(sock_fd);
                close(net_fd);
                exit(0);
            } else {
                do_debug("read %i bytes from pipe \n", n);
                int i;
                for (i = 0; i < 32; i++) {
                    key[i] = buf[i];
                }
                int j = 0;
                for (i = 32; i < 48; i++) {
                    iv[j] = buf[i];
                    j++;
                }
                keysInitialized = 1;
            }
            //do_debug("read: %s from tcp process \n", buf);
        }
    }

    return (0);
}
