#include "crypto.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "cmd.h"
#include "util.h"
#include "ttp.h"

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

int sign(struct api_msg* msg, EVP_PKEY *key){
    assert(msg);
    assert(key);
    memset(msg->sig,0,SIG_LENGTH);
    memset(msg->time,0,sizeof(msg->time));
    unsigned char *sig; unsigned siglen;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if(!ctx){
        printf("could not crate ctx\n");
        return -1;
    }
    sig = malloc(EVP_PKEY_size(key));
    int r = 0;
    r += EVP_SignInit(ctx, EVP_sha256());
    r += EVP_SignUpdate(ctx,msg,sizeof(struct api_msg));
    r += EVP_SignFinal(ctx, sig, &siglen, key);
    if(r != 3){
        printf("error while computing the signature for signing\nr= %d\n",r);
        if(ctx) EVP_MD_CTX_free(ctx);
        if(sig) free(sig);
        return -1;
    }

    memcpy(msg->sig, sig, siglen);

    if(ctx) EVP_MD_CTX_free(ctx);
    if(sig) free(sig);

    return 0;
}

int verify_sig(struct api_msg* msg, char *usr){
    assert(msg);
    unsigned char temp[SIG_LENGTH];
    memset(temp,0,SIG_LENGTH);
    memcpy(temp,msg->sig,SIG_LENGTH);
    memset(msg->sig,0,SIG_LENGTH);
    char time[sizeof(msg->time)];
    memcpy(time,msg->time,sizeof(time));
    memset(msg->time,0,sizeof(msg->time));

    X509 *usrcert = X509_new();

    get_cert(usrcert,usr);
    if(!usrcert){
        printf("could not load user's certificate for %s\n",usr);
        X509_free(usrcert);
        return -1;
    }

    X509_NAME *name;
    name = X509_get_subject_name(usrcert);
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
    char *commonName = malloc(len + 1);
    X509_NAME_get_text_by_NID(name, NID_commonName, commonName, len + 1);
    printf("common name: %s\n", commonName);

    if(strncmp(commonName,usr, strlen(commonName)) != 0){
        printf("username does not match common name\n");
        free(commonName);
        X509_free(usrcert);
        return -1;
    }
    EVP_PKEY *pubkey = X509_get0_pubkey(usrcert);

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if(!ctx){
        printf("could not crate ctx\n");
        return -1;
    }


    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx,msg,sizeof(struct api_msg));
    int r = EVP_VerifyFinal(ctx, temp,SIG_LENGTH , pubkey);
    printf("signature is %s\n", (r == 1) ? "good" : "bad");

    EVP_MD_CTX_free(ctx);

    free(commonName);
    X509_free(usrcert);

    memcpy(msg->sig,temp,SIG_LENGTH);
    memcpy(msg->time,time,sizeof(time));
    return (r == 1) ? 0 : -1;


}

