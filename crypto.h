#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#define SHA256_HASH_SIZE EVP_MD_size(EVP_sha256())
#include "api.h"
int generate_salt(unsigned char *salt);

int hash_salt_password(unsigned char *salt, unsigned char *hash, char *password);

int hash_password(unsigned char *hash, char *password);
int sign(struct api_msg* msg, EVP_PKEY *key);
int verify_sig(struct api_msg* msg, char *usr);

#endif