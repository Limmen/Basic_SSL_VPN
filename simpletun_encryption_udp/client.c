#include "client.h"

/**
 * Function to interact with user through stdIn and retrieve hostname and port of remote host to establish secure
 * channel
 *
 * @param serverName buffer to store hostname
 * @param serverPort buffer to store port
 */
void get_server_details(char *serverName, char *serverPort){
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
int client_secure_channel(int pipefd[2]) {
    close(pipefd[0]); // close the read-end of the pipe
    char serverName[32];
    char serverPort[5];
    BIO *sbio, *out;
    int len;
    char *message;
    unsigned char bytestream[512];
    unsigned char tmpbuf[1000];

    SSL_CTX *ctx;
    SSL *ssl;
    RSA *privKey;
    FILE *file;
    unsigned int numLength;
    unsigned int sigLength;
    unsigned char *signature;

    /**
     * Get host + port of server to initiate secure channel
     */
    get_server_details(serverName, serverPort);

    /**
     * Initialize SSL libraries
     */
    SSL_library_init();
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();

    /* We would seed the PRNG here if the platform didn't
     * do it automatically through /dev/urandom
     */

    /**
     * Initialize SSL_CTX object with cipher/key/cert configurations that then can be reused for many SSL connections.
     * Certificate used is  "server.crt"
     * Private key used is "server.key"
     * Check_private_key means that the private key will be verified against the certificate used.
     * SSL_v23 means that the context object supports SSL connections that understand SSLv3, TLSv1, TLSv1.1 and TLSv1.2
     */
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!SSL_CTX_use_certificate_file(ctx, "certs_and_keys/server.crt", SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ctx, "certs_and_keys/server.key", SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Error setting up SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return (0);
    }

    /* We'd normally set some stuff like the verify paths and
     * mode here because as things stand this will connect to
     * any server whose certificate is signed by any CA.
     */

    /**
     * Creates new BIO (abstraction for input/output source that allows to use same method calls despite the
     * underlying IO mechanism) connect object that uses the SSL context.
     */
    sbio = BIO_new_ssl_connect(ctx);

    /**
     * Retrieves SSL pointer (SSL *) of the BIO, which we can use to invoke the SSL library functions
     */
    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        /* whatever ... */
    }

    /**
     * Don't want any retries
     */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* We might want to do other things with ssl here */

    /**
     * Sets serverName as the remote hostname of the BIO
     * Sets serverPort as the remote port of the BIO
     */
    BIO_set_conn_hostname(sbio, serverName);
    BIO_set_conn_port(sbio, serverPort);


    /**
     * Attempts to connect the bio. Returns 1 if connection was established successfully.
     */
    printf("Attempting to to connect to the server... ");
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(sbio);
        BIO_free(out);
        SSL_CTX_free(ctx);
        exit(1);
    }
    printf("SUCCESS!\n");

    /**
     * Attemps to initiate an SSL handshake on the sbio. Returns 1 if connection was established successfully
     */
    printf("Initiating SSL handshake with the server... ");
    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(sbio);
        BIO_free(out);
        SSL_CTX_free(ctx);
        exit(1);
    }
    printf("SUCCESS!\n");

    /**
     * Connection is already set up, now we await random number from server with BIO_read()
     */
    printf("Waiting for secret from server... ");
    memset(tmpbuf, '\0', sizeof(tmpbuf));
    memset(bytestream, '\0', sizeof(bytestream));
    len = BIO_read(sbio, tmpbuf, 512);
    memcpy(bytestream, &tmpbuf, 512);
    printf("SUCCESS!");
    write(pipefd[1], bytestream, 512);

    while (1) {
        printf("Enter 1 to generate new bytestream to establish new private key and IV with server:\n");
        printf("> ");
        int choice;
        scanf("%d", &choice);
        /**
         * First seeds the RNG then generates random number
         */
        srand((unsigned char) time(NULL));
        int i;
        for (i = 0; i < 512; i++) {
            bytestream[i] = rand() % 256;
        }

        /**
         * Write the generated random number to the tunnel-process to be used for encryption
         */
        write(pipefd[1], bytestream, 512);

        /**
         * Send the random over the secure channel to the client
         */
        printf("Sending the secret to the server...");
        if (BIO_write(sbio, bytestream, 512) <= 0) {
            fprintf(stderr, "Error in sending secret\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("SUCCESS!\n");
    }
    close(pipefd[0]);
}

  