#include "server.h"

/**
 * Function for the server role in a secure channel over TLS/SSL. The channel is used for establishing keys and IV's
 * to be used for VPN-tunneling.  -- Derived from server.c provided by lab-TA in KTH IK2206
 *
 * @param pipefd pipe to communicate with VPN tunnel
 * @return 0 if no errors
 */
int server_secure_channel(int pipefd[2]) {
    close(pipefd[0]); // close the read-end of the pipe
    BIO *sbio, *bbio, *acpt, *out;
    int len;
    unsigned char bytestream[48]; //256 bit key + 128 bit IV to be used for AES256
    unsigned char tmpbuf[100];
    char *ciphertext;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *client_cert;
    char *str;
    SSL_METHOD *meth;
    int err;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    size_t client_len;

    /* SSL preliminaries. We keep the certificate and key with the context. */

    /**
     * SLL_load_error_strings registers error strings for libcrypto and libssl.
     * This call is required to later be able to generate textual error messages.
     */
    SSL_load_error_strings();
    /**
     * Initialize SSL library by registering algorithms (i.e registers available ciphers and digests for SSL/TLS)
     */
    SSLeay_add_ssl_algorithms();
    /**
     * method v23 means that the SSL/TLS connection will understand  SSLv3, TLSv1, TLSv1.1 and TLSv1.2
     */
    meth = (SSL_METHOD *) SSLv23_server_method();
    /**
     * Creates a new context object (ctx) as a framework for TLS/SSL functions, the object uses the method for the connections
     */
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    /**
     * Sets peer certificate verification parameters
     * SSL_VERIFY_PEER means that the server will send a request for client-certificate in the handshake
     * (client authentication is not required by default in TLS/SSL).
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /* whether verify the certificate */
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
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    /**
     * Checks that the configured private key is consistent with the configured certificate
     */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }

    /* ----------------------------------------------- */
    /* Prepare TCP socket for receiving connections */

    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    memset(&sa_serv, '\0', sizeof(sa_serv)); //Initialize sa_serv to 0's, sa_serv is socket info for our endpoint
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(1111);          /* Server Port number */

    /**
     * Binds the socket to the given address
     */
    err = bind(listen_sd, (struct sockaddr *) &sa_serv,
               sizeof(sa_serv));
    CHK_ERR(err, "bind");

    /* Receive a TCP connection. */

    /**
     * Prepares socket for listening for incoming connections
     */
    err = listen(listen_sd, 5);
    CHK_ERR(err, "listen");

    client_len = sizeof(sa_cli);
    printf("Server listening for incoming connections.. \n");
    /**
     * Blocking call for accepting incoming client connections
     */
    sd = accept(listen_sd, (struct sockaddr *) &sa_cli, (socklen_t *) &client_len);
    CHK_ERR(sd, "accept");
    close(listen_sd); //Not gonna listen for any more connections
    printf("Connection from %d, port %x\n",
           sa_cli.sin_addr.s_addr, sa_cli.sin_port);

    /* ----------------------------------------------- */
    /* TCP connection is ready. Do server side SSL. */

    /**
     * SSL_new() creates a new SSL structure which is needed to hold the data for a TLS/SSL connection.
     * The new structure inherits the settings of the underlying context ctx: connection method (SSLv2/v3/TLSv1),
     * options, verification settings, timeout settings.
     */
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    /**
     * SSL_set_fd() sets the file descriptor sd as the input/output facility for the TLS/SSL (encrypted) side of ssl.
     * sd will typically be the socket file descriptor of a network connection
     */
    SSL_set_fd(ssl, sd);
    /**
     * Blocking call, waiting for client to initiate TLS/SSL handshake
     * Only returns after handshake is finnished or error occurred.
     */
    err = SSL_accept(ssl);
    CHK_SSL(err);

    /* Get the cipher - opt */

    /**
     * SSL_get_cipher is a macto for obtaining the name of the currently used cipher of the connection.
     */
    printf("SSL connection using %s\n", SSL_get_cipher (ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    /**
     * SSL_get_peer_certificate() returns a pointer to the X509 certificate the peer presented during the handshake.
     * If the peer did not present a certificate, NULL is returned.
     */
    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        printf("Client certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t subject: %s\n", str);
        OPENSSL_free (str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t issuer: %s\n", str);
        OPENSSL_free (str);

        /* We could do all sorts of certificate verification stuff here before
           deallocating the certificate. */

        X509_free(client_cert); //Frees the datastructure holding the client cert
    } else
        printf("Client does not have certificate.\n");

    /**
     * First seeds the RNG then generates random key and IV
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
     * Send the random key over the secure channel to the client
     */
    printf("Sending the secret to the client...");
    //printf("key is %s... \n", key);
    if (BIO_write(sbio, bytestream, 48) <= 0) {
        fprintf(stderr, "Error in sending secret\n");
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("SUCCESS!\n");

    /**
     * Flushes any leftover data
     */
    BIO_flush(sbio);
    while (1) {
        printf("Waiting for secret from client... ");
        memset(tmpbuf, '\0', sizeof(tmpbuf));
        memset(bytestream, '\0', sizeof(bytestream));
        len = BIO_read(sbio, tmpbuf, 48);
        if (len == 0) {
            printf("FAILURE!\n remote end of socket closed by client.\n");
            break;
        }
        memcpy(bytestream, &tmpbuf, 48);
        printf("SUCCESS!\n");
        write(pipefd[1], bytestream, 48);
    }

    /**
     * Cleanup
     */
    close(pipefd[0]);

}