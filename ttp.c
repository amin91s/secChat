//
// Created by Amin Soleimani on 26/11/2022.
//
#include "ttp.h"
#include <assert.h>
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cmd.h"
#include <fcntl.h>
#include "crypto.h"




int sign_csr(char *usr, char *passwd){
    assert(usr);
    assert(passwd);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    if(!check_length(passwd, MIN_PASS_LENGTH,MAX_PASS_LENGTH)){
        printf("incorrect password length\n");
        return -1;
    }
    char temp2[256];
    memset(temp2, 0, 256);
    snprintf(temp2, 256, "clientkeys/%s/%s-csr.pem", usr, usr);
    if(!fileExists(temp2)){
        printf("csr does not exist\n");
        return -1;
    }
    if(validate_clientkey_access(usr,passwd) == 0){
        //sign csr
        char temp[256];
        memset(temp,0,256);
        snprintf(temp,256,"clientkeys/%s/%s-ca-cert.pem",usr,usr);
        if(exec((char *[]){"/usr/bin/openssl", "x509", "-req", "-CA",  "ttpkeys/ca-cert.pem", "-CAkey" ,"ttpkeys/ca-key.pem" ,"-CAcreateserial", "-in", temp2, "-out", temp,NULL}) != 0){
            printf("could not generate user cert.\n");
            return -1;
        }
        return 0;
    }
    return -1;
}



int gen_rsa(char *usr, char *passwd){
    assert(usr);
    assert(passwd);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    if(!check_length(passwd, MIN_PASS_LENGTH,MAX_PASS_LENGTH)){
        printf("incorrect password length\n");
        return -1;
    }

    char temp[256];
    memset(temp, 0, 256);
    snprintf(temp, 256, "clientkeys/%s", usr);

    if(fileExists(temp)){
        printf("directory already exists\n");
        return -1;
    }
    //make directory
    if(exec((char *[]){"/bin/mkdir","-p",temp, NULL}) != 0){
        printf("could not make usr key directory\n");
        return -1;
    }

    //generate key
    memset(temp, 0, 256);
    snprintf(temp, 256, "clientkeys/%s/%s-key.pem", usr, usr);
    if(exec((char *[]){"/usr/bin/openssl","genrsa", "-out", temp,NULL}) != 0){
        printf("could not generate priv key\n");
        return -1;
    }
    //generate csr
    char temp2[256];
    memset(temp2, 0, 256);
    snprintf(temp2, 256, "clientkeys/%s/%s-csr.pem", usr, usr);

    char temp3[256];
    memset(temp3, 0, 256);
    snprintf(temp3, 256, "/CN=%s", usr);

    if(exec((char *[]){"/usr/bin/openssl","req", "-new",  "-key",temp, "-out", temp2, "-nodes", "-subj", temp3, NULL}) != 0){
        printf("could not generate user cert.\n");
        return -1;
    }
    //sign csr
    memset(temp,0,256);
    snprintf(temp,256,"clientkeys/%s/%s-ca-cert.pem",usr,usr);

    if(exec((char *[]){"/usr/bin/openssl", "x509", "-req", "-CA",  "ttpkeys/ca-cert.pem", "-CAkey" ,"ttpkeys/ca-key.pem" ,"-CAcreateserial", "-in", temp2, "-out", temp,NULL}) != 0){
        printf("could not generate user cert.\n");
        return -1;
    }

    //hash the password
    unsigned char *hash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
    if(hash_password(hash,passwd) != 0){
        free(hash);
        return -1;
    }
    //save password's hash
    FILE *fp;
    memset(temp,0,256);
    snprintf(temp,256,"clientkeys/%s/hash.bin",usr);
    fp = fopen(temp,"wb");
    if(fp == NULL) {
        printf("file can't be opened\n");
        free(hash);
        return -1;
    }
    if(fwrite(hash,1,SHA256_HASH_SIZE,fp) <= 0){
        printf("could not write hash to file\n");
        free(hash);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    free(hash);
    return 0;

}

int get_priv_key(EVP_PKEY *key, char *usr, char *pass){
    assert(pass);
    assert(usr);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    if(!check_length(pass, MIN_PASS_LENGTH,MAX_PASS_LENGTH)){
        printf("incorrect password length\n");
        return -1;
    }

    ///todo: implement goto cleanup

    //check if password is correct
    if(validate_clientkey_access(usr,pass) == 0){
        char path[256];
        memset(path,0,256);
        snprintf(path,256,"clientkeys/%s/%s-key.pem",usr,usr);
        FILE *keyfile = fopen(path, "r");
        if(keyfile == NULL){
            printf("file can't be opened\n");
            return -1;
        }
        RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
        if(!rsa){
            printf("could not read rsa from pem\n");
            //todo: goto cleanup
            fclose(keyfile);
            return -1;
        }
        fclose(keyfile);
        EVP_PKEY_assign_RSA(key, rsa);
        //printPkey(key);
        return 0;
    }
    return -1;
}

//this function verifies the certificate
//usrcert is freed by caller
// 1 if user does not exist
int get_cert(X509 *usrcert, char *usr){
    assert(usr);
    EVP_PKEY *capubkey;
    X509 *cacert;

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    ///todo: implement goto cleanup

    FILE *path = fopen("ttpkeys/ca-cert.pem", "r");
    if(path == NULL){
        printf("could not load cacert\n");
        return -1;
    }
    cacert = PEM_read_X509(path, NULL, NULL, NULL);
    capubkey = X509_get0_pubkey(cacert);

    char buf[256];
    memset(buf,0,256);
    snprintf(buf,256,"clientkeys/%s/%s-ca-cert.pem",usr,usr);
    fclose(path);
    if(!fileExists(buf)){
        //printf("user does not exist\n");
        X509_free(cacert);
        return 1;
    }
    path = NULL;
    path = fopen(buf,"r");
    if(path == NULL){
        printf("could not load user's cert\n");
        X509_free(cacert);
        return -1;
    }
    usrcert = PEM_read_X509(path, &usrcert, NULL, NULL);
    /* verify CA signature */
    int r = X509_verify(usrcert, capubkey);

    if(r != 1){
        printf("certificate is not correctly signed by CA\n");
        X509_free(cacert);
        fclose(path);
        return -1;
    }

    X509_free(cacert);
    fclose(path);
    return 0;
}

int receiver_exists(char *usr){
    assert(usr);
    X509 *usrcert = X509_new();
    int r = get_cert(usrcert,usr);
    X509_free(usrcert);
    return r == 0 ? 1:0;
}