#ifndef _API_H_
#define _API_H_

#include "cmd.h"
#include <openssl/ssl.h>
#include "ssl-nonblock.h"


struct api_msg
{
  enum cmd_type type;
  char time[20];
  unsigned char sig[256];
  union {
      struct public_msg publicMsg;
      struct private_msg privateMsg;
      struct auth auth;
      struct users users;
      struct server_response serverResponse;
      struct key_exchange keyExchange;
  };

};

struct api_state
{
  int fd;
};

int api_recv(struct api_state *state, struct api_msg *msg, SSL* ssl);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);

/* TODO add API calls to send messages to perform client-server interactions */

int api_send(int fd, struct api_msg *msg, SSL* ssl);
void set_time(char *temp);
int send_response(int fd, enum response, char *text, SSL *ssl);
int receiver_exists(char *usr);


#endif /* defined(_API_H_) */
