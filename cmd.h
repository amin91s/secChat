/*
* Framework file that holds the structure of the commands and constants used throughout the program.
* Created by Amin Soleimani on 12/11/2021.
*/

#ifndef _CMD_H_
#define _CMD_H_
#include <time.h>

#define MAX_MESSAGE_LENGTH 512
#define MAX_USR_LENGTH 15
#define MAX_PASS_LENGTH 15
#define MIN_USR_LENGTH 2
#define MIN_PASS_LENGTH 2
#define MAX_HASH_LENGTH 64
#define SALT_LENGTH 32
#define MAX_RESPONSE_LENGTH 64
#define MAX_CHILDREN 16
#define SLOW_HASH_ROUNDS 1000
#define SIG_LENGTH 256
enum cmd_type
{
    CMD_LOGIN = 0,
    CMD_PRIVATE_MSG = 1,
    CMD_PUBLIC_MSG = 2,
    AES_KEY_INSERT= 3,
    AES_KEY_REQUEST= 4,
    CMD_REGISTER= 5,
    CMD_USERS=6,
    SERVER_RESPONSE=7
};

enum response{
    REG_SUCCESSFUL,
    LOGIN_SUCCESSFUL,
    INVALID_CREDENTIALS,
    CMD_NOT_AVAILABLE,
    USER_NOT_FOUND,
    USER_DOES_NOT_MATCH,
    USERNAME_EXISTS,
    INVALID_CMD_FORMAT,
    INVALID_USR_LEN,
    INVALID_PSW_LEN,
    ALREADY_LOGGED_IN,
    KEY_ALREADY_EXISTS,
    KEY_NOT_FOUND,
    KEY_INSERT_SUCCESSFUL

};



struct public_msg{
    char message[MAX_MESSAGE_LENGTH+1];
    char sender[MAX_USR_LENGTH+1];

};


struct private_msg{
    char message[MAX_MESSAGE_LENGTH+1];
    char sender[MAX_USR_LENGTH+1];
    char receiver[MAX_USR_LENGTH + 1];
    int len;
};
//used for both login and register
struct auth{
    char username[MAX_USR_LENGTH+1];
    char password[MAX_PASS_LENGTH+1];

};
struct users{
   char users[MAX_CHILDREN][MAX_USR_LENGTH+1];
   int num_users;
};

struct server_response{
    enum response response;
    char message[MAX_RESPONSE_LENGTH+1];
};

struct key_exchange{
    char key[MAX_MESSAGE_LENGTH+1];
    int keyLen;
    unsigned char iv[MAX_MESSAGE_LENGTH+1];
    char sender[MAX_USR_LENGTH+1];
    char receiver[MAX_USR_LENGTH + 1];
};

#endif
