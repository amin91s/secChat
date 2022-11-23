#include "crypto.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/rand.h>

int generate_salt(unsigned char *salt){
    assert(salt);
    if( RAND_bytes(salt,SALT_LENGTH) != 1){
        printf("could not generate random salt\n");
        return -1;
    }
    return 0;
}