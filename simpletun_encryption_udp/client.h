#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CERTF "certs_and_keys/client.crt"
#define KEYF "certs_and_keys/client.key"
#define CACERT "certs_and_keys/ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int client_secure_channel(int pipefd[2]);