#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <openssl/evp.h>
#include "crypto.h"
int lookup_host_ipv4(const char *hostname, struct in_addr *addr);
int max(int x, int y);
int parse_port(const char *str, uint16_t *port_p);
int check_length(char *text, int minLen, int maxLen);
void printHex(int size,unsigned char *buf);
int validatePath(char *path);
void printPkey(EVP_PKEY *key);
int validate_clientkey_access(char *usr, char *pass);
int fileExists(const char *filename);

#endif /* defined(_UTIL_H_) */
