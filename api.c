#include <assert.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

#include "api.h"



/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg, SSL *ssl)
{

  assert(state);
  assert(msg);
  assert(ssl);

  //size_t ret = read(state->fd, msg, sizeof(struct api_msg));

  ssize_t ret = ssl_block_read(ssl,state->fd,msg,sizeof(struct api_msg));
  //printf("api_recv: %zd\n",ret);
  return ret > 0 ? 1 : ret;
}

//todo: check if size is needed after adding encryption
int api_send(int fd, struct api_msg *msg, SSL *ssl)
{
  assert(msg);
  assert(ssl);
  //size_t ret = send(fd, msg, sizeof(*msg), 0);
  size_t ret = ssl_block_write(ssl,fd,msg,sizeof(*msg));
  //printf("api_send: %zu\n",ret);
  return ret > 0 ? 0 : -1;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg)
{

  assert(msg);

  /* clean up state allocated for msg */

  memset(msg, 0, sizeof(*msg));
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state)
{

  assert(state);

  /* TODO clean up API state */
  memset(state, 0, sizeof(*state));
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd)
{

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;
}


/* Sets time for client */
void set_time(char *temp)
{
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(temp, 20, "%Y-%m-%d %H:%M:%S", info);
}

int send_response(int fd,enum response r,char *text, SSL *ssl){
    struct api_msg msg;
    msg.type=SERVER_RESPONSE;
    set_time(msg.time);
    msg.serverResponse.response = r;
    if(text != NULL){
        strncpy(msg.serverResponse.message,text,MAX_RESPONSE_LENGTH);
    }
    return api_send(fd,&msg,ssl);

}