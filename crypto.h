#ifndef _CRYPTO_H_
#define _CRYPTO_H_



int generate_salt(unsigned char *salt);

int hash_password(unsigned char *salt, unsigned char *hash, char *password);


#endif