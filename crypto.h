#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SHA256_HASH_SIZE EVP_MD_size(EVP_sha256())
#define CIPHER_TYPE EVP_aes_128_cbc()
#define SYMM_KEY_LEN EVP_CIPHER_key_length(CIPHER_TYPE)
#define IV_LEN EVP_CIPHER_iv_length(CIPHER_TYPE)
#define RSA_KEY_SIZE 256

#include "api.h"
#include "cmd.h"

int generate_salt(unsigned char *salt);

int hash_salt_password(unsigned char *salt, unsigned char *hash, char *password);

int hash_password(unsigned char *hash, char *password);
int sign(struct api_msg* msg, EVP_PKEY *key);
int verify_sig(struct api_msg* msg, char *usr);
int generate_symm_key(char *usr, char *pass, char *receiver);
int aes_enc(char *sender , char *pass, char *receiver, unsigned char *plaintext, unsigned char *ciphertext, int *enc_len);
int aes_dec(char *receiver , char *pass, char *sender, unsigned char *ciphertext, unsigned char *plaintext, int *enc_len);
int get_aes_key(char *usr, char *pass, char *receiver, unsigned char *key, unsigned char *iv);
int rsa_enc(X509 *usrcert, unsigned char *inbuf, unsigned char **outbuf);
int rsa_dec(EVP_PKEY *key, unsigned char *inbuf, unsigned char **outbuf);
int rsa_enc2(X509 *usrcert, unsigned char *inbuf, unsigned char **outbuf);
int send_key(int fd, char *usr, char *pass, char *receiver ,SSL *ssl,  EVP_PKEY *evpKey, unsigned char *tmpKey, unsigned char *tmpIv);
int request_key(int fd, char *usr, char *receiver ,SSL *ssl,  EVP_PKEY *evpKey);
int write_aes_key(char *usr, char *pass, char *receiver, unsigned char *key, unsigned char *iv);
int generate_symm_key_not_stored(char *usr, char *receiver, unsigned char *key, unsigned char *iv);
int gen_csr(char *usr, char *passwd);
#endif