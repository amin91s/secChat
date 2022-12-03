#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include<sys/stat.h>
#include "util.h"

int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  assert(hostname);
  assert(addr);

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host) {
    if (host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      assert(host->h_length == sizeof(*addr));
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  fprintf(stderr, "error: unknown host: %s\n", hostname);
  return -1;
}

int max(int x, int y) {
  return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p) {
  char *endptr;
  long value;

  assert(str);
  assert(port_p);

  /* convert string to number */
  errno = 0;
  value = strtol(str, &endptr, 0);
  if (!value && errno) return -1;
  if (*endptr) return -1;

  /* is it a valid port number */
  if (value < 0 || value > 65535) return -1;

  *port_p = value;
  return 0;
}

int check_length(char *text, int minLen, int maxLen){
    size_t len = strlen(text);
   return (len >= minLen && len <= maxLen );

}

void printHex(int size, unsigned char *buf){
    for(int j = 0; j < size; j++)
        printf("%02X",buf[j]);
    printf("\n");

}

void printPkey(EVP_PKEY *key){
    assert(key);
    printf("pkey:\n");
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(bp, key, 1, NULL);
    BIO_free(bp);
}



/**
 * @brief               Validates access to client's keys.
 * @param               usr sanitized username
 * @return              0 for correct password, 1 for wrong password, -1 on errors.
 */
int validate_clientkey_access(char *usr, char *pass){
    assert(usr);
    assert(pass);

    unsigned char *hash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
    if(hash_password(hash,pass) != 0){
        free(hash);
        return -1;
    }

    FILE *fp;
    char path[256];
    memset(path,0,256);
    snprintf(path,256,"clientkeys/%s/hash.bin",usr);
    fp = fopen(path,"rb");
    if(fp == NULL) {
        printf("file can't be opened\n");
        free(hash);
        return -1;
    }

    unsigned char *storedHash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
    if(fread(storedHash,1,SHA256_HASH_SIZE,fp) <= 0){
        printf("could not read the hash file\n");
        free(hash);
        free(storedHash);
        fclose(fp);
        return -1;
    }
    if(memcmp(storedHash,hash,SHA256_HASH_SIZE) !=0){
        printf("wrong password! you can't access keys.\n");
        free(hash);
        free(storedHash);
        fclose(fp);
        return 1;
    }

    free(hash);
    free(storedHash);
    fclose(fp);
    return 0;
}

/**
 * @param               usr sanitized path
 */
int fileExists(const char *filename){
    struct stat buffer;
    return (stat(filename,&buffer) == 0);

}