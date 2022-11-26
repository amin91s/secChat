#include "crypto.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "cmd.h"
#include <openssl/rand.h>
#include "util.h"

int generate_salt(unsigned char *salt){
    assert(salt);
    if( RAND_bytes(salt,SALT_LENGTH) != 1){
        printf("could not generate random salt\n");
        return -1;
    }
    return 0;
}

//ret 0 on success
int hash_salt_password(unsigned char *salt, unsigned char *hash, char *password){
    assert(salt);
    assert(hash);
    assert(password);

    //TODO: add goto cleanup

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx){
        printf("could not create context\n");
        return -1;
    }
    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1){
        printf("could not initialize context\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_DigestUpdate(ctx, salt, SALT_LENGTH);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    //printf("initial hash:\n");
    //printHex(SALT_LENGTH, hash);


    int r = 0;
    for(int i=0; i < SLOW_HASH_ROUNDS; i++){
        r += EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        r += EVP_DigestUpdate(ctx, salt, SALT_LENGTH);
        r += EVP_DigestUpdate(ctx, password, strlen(password));
        r += EVP_DigestUpdate(ctx, hash, SALT_LENGTH);
        r += EVP_DigestFinal_ex(ctx, hash, NULL);
    }
    if(r != (SLOW_HASH_ROUNDS*5)){
    	printf("slow hash failed\n");
    	EVP_MD_CTX_free(ctx);
        return -1;
    }
    //printf("hash after %d rounds:\n",SLOW_HASH_ROUNDS);
    //printHex(SALT_LENGTH, hash);


    EVP_MD_CTX_free(ctx);
    return 0;
}


int hash_password(unsigned char *hash, char *password){
    assert(hash);
    assert(password);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx){
        printf("could not create context\n");
        return -1;
    }
    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1){
        printf("could not initialize context\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash, NULL);

    //printf("hash(no salt):\n");
    //printHex(SALT_LENGTH, hash);

    EVP_MD_CTX_free(ctx);
    return 0;
}