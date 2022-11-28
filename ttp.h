//
// Created by Amin Soleimani on 26/11/2022.
//

#ifndef FRAMEWORK_TTP_H
#define FRAMEWORK_TTP_H
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


int gen_rsa(char *usr, char *passwd);


int get_priv_key(EVP_PKEY *key, char *usr, char *pass);
int get_cert(X509 *usrcert, char *usr);
#endif //FRAMEWORK_TTP_H
