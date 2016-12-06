#include "client.h"

/**
 * Function to interact with user through stdIn and retrieve hostname and port of remote host to establish secure
 * channel -- Derived from server.cpp provided by lab-TA in KTH IK2206
 *
 * @param serverName buffer to store hostname
 * @param serverPort buffer to store port
 */
void get_server_details(char *serverName, char *serverPort) {
    printf("Enter server host name: ");
    scanf("%s", serverName);
    printf("Enter server port: ");
    scanf("%s", serverPort);
}

/**
 * Function for the client role in a secure channel over TLS/SSL. The channel is used for establishing keys and IV's
 * to be used for VPN-tunneling.  -- Derived from client.c provided by lab-TA KTH in IK2206
 *
 * @param pipefd pipe to communicate with VPN tunnel
 * @return 0 if successful
 */
int client_secure_channel(int pipefd[2], pid_t ppid) {
    close(pipefd[0]); // close the read-end of the pipe
    char serverName[32];
    char serverPort[5];
    unsigned char bytestream[48]; //256 bit key + 128 bit IV to be used for AES256
    unsigned char tmpbuf[100];
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *server_cert;
    char *str;
    int err;
    int sd;
    struct sockaddr_in sa;
    SSL_METHOD *meth;

    /**
     * Get host + port of server to initiate secure channel
     */
    get_server_details(serverName, serverPort);


    /**
     * SSL initialization
     */
    SSLeay_add_ssl_algorithms();
    meth = (SSL_METHOD *) SSLv23_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);
    CHK_SSL(err);

    /**
     * Sets peer certificate verification parameters
     * SSL_VERIFY_PEER means that the client will send a request for server-certificate in the handshake
     * NULL because we don't need explicit callback for verification, use openSSL default verification
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /**
     * Set default locations for trusted CA certs (CACERT => ca.crt), NULL means that there is not needed to provide
     * a path since we are in right directory.
     */
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);


    /**
     * These functions load the certificates and private keys into the SSL_CTX or SSL object, respectively.
     * Later when we create connections from the CTX object, the keys/certs will be used.
     */
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-3);
    }

    /**
     * Checks that the configured private key is consistent with the configured certificate
     */
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key \n");
        exit(-4);
    }

    /* Create a socket and connect to server using normal socket calls. */

    /**
     * Creates normal TCP socket
     */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    /**
     * Setup server adress info
     */
    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(serverName);   /* Server IP */
    sa.sin_port = htons(atoi(serverPort));          /* Server Port number */

    /**
     * Tries to open up a TCP connection to the server
     */
    err = connect(sd, (struct sockaddr *) &sa,
                  sizeof(sa));
    CHK_ERR(err, "connect");

    /* ----------------------------------------------- */
    /* Now we have TCP conncetion. Start SSL negotiation. */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    SSL_set_fd(ssl, sd);
    /**
     * SSL_connect() initiates the TLS/SSL handshake with a server.
     * (Server is using SSL_accept to participate in the handshake)
     */
    err = SSL_connect(ssl);
    CHK_SSL(err);

    /* Following two steps are optional and not required for
       data exchange to be successful. */

    /* Get the cipher - opt */

    printf("SSL connection using %s\n", SSL_get_cipher (ssl));
    /* Get server's certificate (note: beware of dynamic allocation) - opt */

    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free (str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free (str);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    X509_free(server_cert);

    /**
     * Connection is already set up, now we await random number from server with BIO_read()
     */
    printf("Waiting for secret from server... ");
    memset(tmpbuf, '\0', sizeof(tmpbuf));
    memset(bytestream, '\0', sizeof(bytestream));
    err = SSL_read(ssl, tmpbuf, 48);
    CHK_SSL(err);
    memcpy(bytestream, &tmpbuf, 48);
    printf("SUCCESS!");
    write(pipefd[1], bytestream, 48);

    while (1) {
        printf("Enter 1 to generate new bytestream to establish new private key and IV with server | enter 2 to exit:\n");
        printf("> ");
        int choice;
        scanf("%d", &choice);
        if(choice == 1) {
            /**
             * First seeds the RNG then generates random number
             */
            srand((unsigned char) time(NULL));
            int i;
            for (i = 0; i < 48; i++) {
                bytestream[i] = rand() % 256;
            }

            /**
             * Write the generated random number to the tunnel-process to be used for encryption
             */
            write(pipefd[1], bytestream, 48);

            /**
             * Send the random over the secure channel to the client
             */
            printf("Sending the secret to the server...");
            err = SSL_write(ssl, bytestream, 48);
            CHK_SSL(err);
            printf("SUCCESS!");
        }
        if(choice == 2){
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            X509_free(server_cert);
            close(sd);
            kill (getppid(), 9);
            break;
        }
        if(choice != 1 && choice != 2){
            printf("Invalid input \n");
        }
    }
    close(pipefd[0]);
}

  