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


    /**
     * Initiate SSL libraries
     */
    SSL_library_init();
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();

    /* Might seed PRNG here */

    /**
     * Initialize SSL_CTX object with cipher/key/cert configurations that then can be reused for many SSL connections.
     * Certificate used is  "server.crt"
     * Private key used is "server.key"
     * Check_private_key means that the private key will be verified against the certificate used.
     * SSL_v23 means that the context object supports SSL connections that understand SSLv3, TLSv1, TLSv1.1 and TLSv1.2
     */
    ctx = SSL_CTX_new(SSLv23_server_method());

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


    /* Might do other things here like setting verify locations and
     * DH and/or RSA temporary key callbacks
     */

    /**
     * Creates new BIO (abstraction for input/output source that allows to use same method calls despite the
     * underlying IO mechanism) server object that uses the SSL context.
     */
    sbio = BIO_new_ssl(ctx, 0);

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

    /**
     * Creates a new BIO object to buffer incoming messages
     */
    bbio = BIO_new(BIO_f_buffer());

    /**
     * Add the buffering bio to the BIO chain
     */
    sbio = BIO_push(bbio, sbio);

    /**
     * Creates a new BIO to accept incoming messages on port 4433
     */
    acpt = BIO_new_accept((char *) "4433");

    /* By doing this when a new connection is established
     * we automatically have sbio inserted into it. The
     * BIO chain is now 'swallowed' by the accept BIO and
     * will be freed when the accept BIO is freed.
     */
    BIO_set_accept_bios(acpt, sbio);

    /**
     * Setup accept BIO
     */
    printf("Setting up the accept BIO... ");
    if (BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        return (0);
    }
    printf("SUCCESS!\n");
    /**
     * Await incoming connection
     */
    printf("Setting up the incoming connection... ");
    if (BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error in connection\n");
        ERR_print_errors_fp(stderr);
        return (0);
    }
    printf("SUCCESS!\n");

    /* We only want one connection so remove and free
     * accept BIO
     */
    sbio = BIO_pop(acpt);

    /**
     * Frees up the entire BIO chain
     */
    BIO_free_all(acpt);

    /**
     * Awaits client to initiate the handshake and then participates in the goal to complete the handshake
     */
    printf("Waiting for SSL handshake...");
    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error in SSL handshake\n");
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("SUCCESS!\n");

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