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

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

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
        if(usrcert) X509_free(usrcert);
        return -1;
    }

    X509_NAME *name;
    name = X509_get_subject_name(usrcert);
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
    char *commonName = malloc(len + 1);
    X509_NAME_get_text_by_NID(name, NID_commonName, commonName, len + 1);
    //printf("common name: %s\n", commonName);

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
        X509_free(usrcert);
        free(commonName);
        return -1;
    }


    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx,msg,sizeof(struct api_msg));
    int r = EVP_VerifyFinal(ctx, temp,SIG_LENGTH , pubkey);
    //printf("signature is %s\n", (r == 1) ? "good" : "bad");
    //printf("common name: %s\n", commonName);
    EVP_MD_CTX_free(ctx);

    free(commonName);
    X509_free(usrcert);

    memcpy(msg->sig,temp,SIG_LENGTH);
    memcpy(msg->time,time,sizeof(time));
    return (r == 1) ? 0 : -1;


}


/**
 *  * @return              0  on success, 1 if key already exists , -1 on error
 */
int generate_symm_key(char *usr, char *pass, char *receiver){
    assert(pass);
    assert(usr);
    assert(receiver);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;
    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;
    if(!check_length(pass, MIN_PASS_LENGTH,MAX_PASS_LENGTH)){
        printf("incorrect password length\n");
        return -1;
    }

    ///todo: implement goto cleanup



    if(validate_clientkey_access(usr,pass) == 0){
        unsigned char key[SYMM_KEY_LEN], iv[(IV_LEN)];
        memset(key,0,SYMM_KEY_LEN);
        memset(iv,0,IV_LEN);
        if( RAND_bytes(key,SYMM_KEY_LEN) != 1){
            printf("could not generate Symmetric-key\n");
            return -1;
        }
        if( RAND_bytes(iv,IV_LEN) != 1){
            printf("could not generate IV\n");
            return -1;
        }
        //store key and iv
        char path[256];
        memset(path, 0, 256);
        snprintf(path,256,"clientkeys/%s/%s-key.dat",usr,receiver);
        //check if key already exists
        if(fileExists(path)){
            printf("key already exists\n");
            return 1;
        }

        FILE *fp;
        fp = fopen(path,"wb");
        if(fp == NULL) {
            printf("file can't be opened\n");
            return -1;
        }
        if(fwrite(key,1,SYMM_KEY_LEN,fp) <= 0){
            printf("could not write Symmetric-key to file\n");
            fclose(fp);
            return -1;
        }
        memset(path,0,256);
        snprintf(path,256,"clientkeys/%s/%s-iv.dat",usr,receiver);
        fclose(fp);
        fp = fopen(path,"wb");
        if(fp == NULL) {
            printf("file can't be opened\n");
            return -1;
        }
        if(fwrite(iv,1,IV_LEN,fp) <= 0){
            printf("could not write IV to file\n");
            //todo: remove key if added.
            fclose(fp);
            return -1;
        }
        fclose(fp);
        return 0;
    }
    return -1;

}

/**
 *  * @return              0  on success , -1 on error
 */
int generate_symm_key_not_stored(char *usr, char *receiver, unsigned char *key, unsigned char *iv){
    assert(usr);
    assert(receiver);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;
    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;

    unsigned char tempKey[SYMM_KEY_LEN], tempIv[(IV_LEN)];
    memset(key,0,SYMM_KEY_LEN);
    memset(iv,0,IV_LEN);

    if( RAND_bytes(tempKey,SYMM_KEY_LEN) != 1){
        printf("could not generate Symmetric-key\n");
        return -1;
    }
    if( RAND_bytes(tempIv,IV_LEN) != 1){
        printf("could not generate IV\n");
        return -1;
    }
    memcpy(key,tempKey,SYMM_KEY_LEN);
    memcpy(iv,tempIv,IV_LEN);

    return 0;

}

/**
 * @param       plaintext paintext
 * @param       ciphertext initialized buffer for cypher-text
 * @return      0  on success, 1 if key does not exist , -1 on error
 */
int aes_enc(char *sender , char *pass, char *receiver, unsigned char *plaintext, unsigned char *ciphertext, int *enc_len){
    assert(sender);
    assert(receiver);
    assert(plaintext);

    if(!valid_username(sender,ALLOWED_USR_CHARS))
        return -1;
    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;

    if((strlen((char*)plaintext) + EVP_CIPHER_block_size(CIPHER_TYPE) + 1) > MAX_MESSAGE_LENGTH){
        printf("plaintext length > max_msg_len\n");
        return -1;
    }

    unsigned char key[SYMM_KEY_LEN], iv[(IV_LEN)];
    memset(key,0,SYMM_KEY_LEN);
    memset(iv,0,IV_LEN);
    int r;
    int len = 0;

    if((r = get_aes_key(sender,pass,receiver,(unsigned char*)key,(unsigned char*)iv)) == 0){
        EVP_CIPHER_CTX *ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())){
            ERR_print_errors_fp(stdout);
            return -1;
        }

        if(1 != EVP_EncryptInit_ex(ctx, CIPHER_TYPE , NULL, key, iv)){
            ERR_print_errors_fp(stdout);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int) strlen((char*)plaintext)+1)) {
            printf("could not encrypt msg\n");
            ERR_print_errors_fp(stdout);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        *enc_len = len;
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
            printf("Error in encrypt final\n");
            ERR_print_errors_fp(stdout);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        *enc_len += len;


        EVP_CIPHER_CTX_free(ctx);

    } else return r;


    return 0;

}

int aes_dec(char *receiver , char *pass, char *sender, unsigned char *ciphertext, unsigned char *plaintext, int *enc_len){
    assert(sender);
    assert(receiver);
    assert(ciphertext);
    assert(enc_len);

    if(!valid_username(sender,ALLOWED_USR_CHARS))
        return -1;

    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;

    if(*enc_len > MAX_MESSAGE_LENGTH){
        printf("ciphertext length > max_msg_len\n");
        return -1;
    }
    unsigned char key[SYMM_KEY_LEN], iv[(IV_LEN)];
    int len;
    memset(key,0,SYMM_KEY_LEN);
    memset(iv,0,IV_LEN);
    int temp_enc_len = *enc_len;
    int r;

    if((r = get_aes_key(receiver,pass,sender,(unsigned char*)key,(unsigned char*)iv)) == 0){
        EVP_CIPHER_CTX *ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())){
            ERR_print_errors_fp(stdout);
            return -1;
        }

        if(1 != EVP_DecryptInit_ex(ctx, CIPHER_TYPE , NULL, key, iv)){
            ERR_print_errors_fp(stdout);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, temp_enc_len)) {
            printf("could not dec msg\n");
            ERR_print_errors_fp(stdout);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
            printf("Error in dec final\n");
            ERR_print_errors_fp(stdout);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }


        EVP_CIPHER_CTX_free(ctx);
    } else return r;

    return 0;


}


/**
 *  * @return   0  on success, 1 if key does not exist , -1 on error
 */
int get_aes_key(char *usr, char *pass, char *receiver, unsigned char *key, unsigned char *iv){
    assert(usr);
    assert(pass);
    assert(receiver);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;

    if(!check_length(pass, MIN_PASS_LENGTH,MAX_PASS_LENGTH)){
        printf("incorrect password length\n");
        return -1;
    }
    if(validate_clientkey_access(usr,pass) == 0){
        char path[256];
        memset(path, 0, 256);
        snprintf(path,256,"clientkeys/%s/%s-key.dat",usr,receiver);
        //check if key already exists
        if(!fileExists(path)){
            //printf("AES key does not exist\n");
            return 1;
        }
        FILE *fp;
        fp = fopen(path,"rb");
        if(fp == NULL) {
            printf("file can't be opened\n");
            return -1;
        }
        if(fread(key, 1, SYMM_KEY_LEN, fp) != SYMM_KEY_LEN){
            printf("could not read Symmetric-key from file\n");
            fclose(fp);
            return -1;
        }
        fclose(fp);
        memset(path,0,256);
        snprintf(path,256,"clientkeys/%s/%s-iv.dat",usr,receiver);

        fp = fopen(path,"rb");
        if(fp == NULL) {
            printf("file can't be opened\n");
            return -1;
        }
        if(fread(iv, 1, IV_LEN, fp) != IV_LEN){
            printf("could not read iv from file\n");
            fclose(fp);
            return -1;
        }
        fclose(fp);
        return 0;
    }

    return -1;
}


/**
 *  * @return   0  on success, 1 if key does already exist , -1 on error
 */
int write_aes_key(char *usr, char *pass, char *receiver, unsigned char *key, unsigned char *iv){
    assert(usr);
    assert(pass);
    assert(receiver);
    assert(key);
    assert(iv);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;

    if(!check_length(pass, MIN_PASS_LENGTH,MAX_PASS_LENGTH)){
        printf("incorrect password length\n");
        return -1;
    }

    ///todo: implement goto cleanup

    if(validate_clientkey_access(usr,pass) == 0){
        char path[256];
        memset(path, 0, 256);
        snprintf(path,256,"clientkeys/%s/%s-key.dat",usr,receiver);
        //check if key already exists
        if(fileExists(path)){
            //printf("key already exists\n");
            return 1;
        }

        FILE *fp;
        fp = fopen(path,"wb");
        if(fp == NULL) {
            printf("file can't be opened\n");
            return -1;
        }
        if(fwrite(key,1,SYMM_KEY_LEN,fp) <= 0){
            printf("could not write Symmetric-key to file\n");
            fclose(fp);
            return -1;
        }
        memset(path,0,256);
        snprintf(path,256,"clientkeys/%s/%s-iv.dat",usr,receiver);
        fclose(fp);
        fp = fopen(path,"wb");
        if(fp == NULL) {
            printf("file can't be opened\n");
            return -1;
        }
        if(fwrite(iv,1,IV_LEN,fp) <= 0){
            printf("could not write IV to file\n");
            //todo: remove key if needed.
            fclose(fp);
            return -1;
        }
        fclose(fp);
        return 0;
    }

    return -1;



}
int rsa_enc(X509 *usrcert, unsigned char *inbuf, unsigned char **outbuf){
    assert(usrcert);
    assert(inbuf);

    EVP_PKEY *pubkey;
    pubkey = X509_get0_pubkey(usrcert);
    RSA *key = EVP_PKEY_get0_RSA(pubkey);
    int inlen = SYMM_KEY_LEN;
    if ((inlen > RSA_size(key) - 42) || inlen > MAX_MESSAGE_LENGTH){
        printf("inlen > MAX_MSG_LEN\n");
        return -1;
    }
    *outbuf = calloc(RSA_size(key), sizeof(unsigned char) );
    int r = RSA_public_encrypt(inlen, inbuf, *outbuf, key, RSA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */
    if (r != RSA_size(key)){
        printf("encrypted size != RSA key size\n");
        return -1;
    }

    return r;

}

int rsa_dec(EVP_PKEY *key, unsigned char *inbuf, unsigned char **outbuf){
    assert(key);

    RSA *privKey = EVP_PKEY_get0_RSA(key);
    int inlen = RSA_size(privKey);
    *outbuf = calloc(RSA_size(privKey), sizeof(unsigned char) );
    int res = RSA_private_decrypt(inlen, inbuf, *outbuf, privKey, RSA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */
    if(res == SYMM_KEY_LEN)
        return 0;
    else{
        printf("error: rsa_dec length: %d\n",res);
        return 1;
    }

}
//not used.
int rsa_enc2(X509 *usrcert, unsigned char *inbuf, unsigned char **outbuf){
    assert(usrcert);
    assert(inbuf);

    EVP_PKEY *pubkey;
    pubkey = X509_get0_pubkey(usrcert);
    EVP_PKEY_CTX *ctx;
    size_t outlen;
    int inlen = SYMM_KEY_LEN;
    ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx){
        printf("could not create ctx\n");
        return -1;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        return -1;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        return -1;
    /* Determine buffer length */
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, inbuf, inlen) <= 0)
        return -1;
    *outbuf = OPENSSL_malloc(outlen);
    if (!outbuf)
        return -1;

    if (EVP_PKEY_encrypt(ctx, *outbuf, &outlen, inbuf, inlen) <= 0)
        return -1;

    return 0;
}


int send_key(int fd, char *usr, char *pass, char *receiver ,SSL *ssl,  EVP_PKEY *evpKey , unsigned char *tmpKey, unsigned char *tmpIv){
    assert(fd);
    assert(usr);
    assert(pass);
    assert(receiver);
    assert(ssl);
    assert(evpKey);

    unsigned char key[SYMM_KEY_LEN], iv[(IV_LEN)];
    memset(key,0,SYMM_KEY_LEN);
    memset(iv,0,IV_LEN);
    if(tmpKey != NULL) {
        memcpy(key,tmpKey,SYMM_KEY_LEN);
        memcpy(iv,tmpIv,IV_LEN);
    } else {
        get_aes_key(usr,pass,receiver,(unsigned char*)key,(unsigned char*)iv);
    }
    struct api_msg key_msg;
    memset(&key_msg, 0, sizeof(struct api_msg));
    key_msg.type = AES_KEY_INSERT;
    memcpy(key_msg.keyExchange.sender,receiver,MAX_USR_LENGTH);
    memcpy(key_msg.keyExchange.receiver,usr,MAX_USR_LENGTH);
    memcpy(key_msg.keyExchange.iv, iv, IV_LEN);
    X509 *usrcert = X509_new();
    get_cert(usrcert,key_msg.keyExchange.sender);
    unsigned char *out = NULL;
    key_msg.keyExchange.keyLen = rsa_enc(usrcert, (unsigned char*)key, &out);
    if(key_msg.keyExchange.keyLen != RSA_KEY_SIZE){
        printf("could not encrypt the aes key\n");
        if(out) free(out);
        X509_free(usrcert);
        return -1;
    }
    memcpy(key_msg.keyExchange.key,out,key_msg.keyExchange.keyLen);
    sign(&key_msg,evpKey);
    if(out) free(out);
    X509_free(usrcert);
    int r = api_send(fd,&key_msg,ssl);
    if (r == 0 && (strcmp(key_msg.keyExchange.sender,key_msg.keyExchange.receiver) != 0 )){
        //send key encrypted with our own pub key as well
        memset(&key_msg, 0, sizeof(struct api_msg));
        key_msg.type = AES_KEY_INSERT;
        memcpy(key_msg.keyExchange.sender,usr,MAX_USR_LENGTH);
        memcpy(key_msg.keyExchange.receiver,receiver,MAX_USR_LENGTH);
        memcpy(key_msg.keyExchange.iv, iv, IV_LEN);
        usrcert = X509_new();
        get_cert(usrcert,key_msg.keyExchange.sender);
        out = NULL;
        key_msg.keyExchange.keyLen = rsa_enc(usrcert, (unsigned char*)key, &out);
        if(key_msg.keyExchange.keyLen != RSA_KEY_SIZE){
            printf("could not encrypt the aes key\n");
            if(out) free(out);
            X509_free(usrcert);
            return -1;
        }
        memcpy(key_msg.keyExchange.key,out,key_msg.keyExchange.keyLen);
        sign(&key_msg,evpKey);
        if(out) free(out);
        X509_free(usrcert);
        return api_send(fd,&key_msg,ssl);
    } else return r;
}

int request_key(int fd, char *usr, char *receiver ,SSL *ssl,  EVP_PKEY *evpKey){
    assert(fd);
    assert(usr);
    assert(receiver);
    assert(evpKey);
    assert(ssl);

    if(!valid_username(usr,ALLOWED_USR_CHARS))
        return -1;

    if(!valid_username(receiver,ALLOWED_USR_CHARS))
        return -1;

    struct api_msg key_msg;
    memset(&key_msg, 0, sizeof(struct api_msg));
    key_msg.type = AES_KEY_REQUEST;
    memcpy(key_msg.keyExchange.sender,usr,MAX_USR_LENGTH);
    memcpy(key_msg.keyExchange.receiver,receiver,MAX_USR_LENGTH);
    sign(&key_msg,evpKey);
    return api_send(fd,&key_msg,ssl);
}


int gen_csr(char *usr, char *passwd){
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

    //hash the password
    unsigned char *hash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
    if(hash_password(hash,passwd) != 0){
        free(hash);
        return -1;
    }
    //save password's hash in user's directory
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