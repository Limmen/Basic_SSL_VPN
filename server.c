#include "server.h"
int verifyNumber(char *, char *);

int server_secure_channel(int pipefd[2]) {
    BIO *sbio, *bbio, *acpt, *out;
    int len;
    char number[10];
    char tmpbuf[257];
    char *ciphertext;
    SSL_CTX *ctx;
    SSL *ssl;

    SSL_library_init();
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();

    /* Might seed PRNG here */

    ctx = SSL_CTX_new(SSLv23_server_method());

    if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Error setting up SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return (0);
    }

    /* Might do other things here like setting verify locations and
     * DH and/or RSA temporary key callbacks
     */

    /* New SSL BIO setup as server */
    sbio = BIO_new_ssl(ctx, 0);

    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        /* whatever ... */
    }

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* Create the buffering BIO */

    bbio = BIO_new(BIO_f_buffer());

    /* Add to chain */
    sbio = BIO_push(bbio, sbio);

    acpt = BIO_new_accept((char *) "4433");

    /* By doing this when a new connection is established
     * we automatically have sbio inserted into it. The
     * BIO chain is now 'swallowed' by the accept BIO and
     * will be freed when the accept BIO is freed.
     */

    BIO_set_accept_bios(acpt, sbio);

    /* Setup accept BIO */
    printf("Setting up the accept BIO... ");
    if (BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        return (0);
    }
    printf("SUCCESS!\n");

    /* Now wait for incoming connection */
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

    BIO_free_all(acpt);

    // wait for ssl handshake from the client
    printf("Waiting for SSL handshake...");
    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error in SSL handshake\n");
        ERR_print_errors_fp(stderr);
        return (0);
    }
    printf("SUCCESS!\n");

    X509 *server_cert = SSL_get_certificate(ssl);
    printf("Server cert name: %s, cipher name: \n", server_cert->name);

    printf("Server certificates:\n");
    char *str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    printf("Subject: %s\n", str);
    free(str);
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("Issuer: %s\n", str);
    SSL_SESSION *session;
    if(session->master_key != NULL) {
        unsigned  char * master_key = session->master_key;
        printf("master key not null \n");
        printf("master key length: %i \n",session->master_key_length);
        printf("Master key size: %i \n", (int) sizeof(master_key));
        printf("ssl version: %i \n", session->ssl_version);
        int i = 0;
        for(i; i < sizeof(master_key); i++){
            printf("%i", master_key[i]);
        }
        printf("\n");
    }
    else
        printf("master key is null \n");
    session = SSL_get_session(ssl);

    // generate the random number for the challenge
    srand((unsigned) time(NULL));
    sprintf(number, "%d", rand());

    close(pipefd[0]); // close the read-end of the pipe
    write(pipefd[1], number, strlen(number));
    // send the random number to the client
    printf("Sending the random number challenge to the client. Number is %s... ", number);
    if (BIO_write(sbio, number, strlen(number)) <= 0) {
        fprintf(stderr, "Error in sending random number\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    printf("SUCCESS!\n");
    printf("while true..");
    close(pipefd[0]);
    BIO_flush(sbio);
}