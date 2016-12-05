#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <openssl/hmac.h>

void initializeSSL();
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int verify_MAC(unsigned char *msg, int mlen, unsigned char *sig, int slen, EVP_PKEY* pkey);
unsigned char* addMAC(unsigned char *key, int key_len, unsigned char *cipher_text, int cipher_text_len);
void createPKEY(EVP_PKEY *mac_key, unsigned char *key, int klen);