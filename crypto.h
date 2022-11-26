#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/evp.h>
#define SHA256_HASH_SIZE EVP_MD_size(EVP_sha256())

int generate_salt(unsigned char *salt);

int hash_salt_password(unsigned char *salt, unsigned char *hash, char *password);

int hash_password(unsigned char *hash, char *password);

#endif