#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "db-stuff.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl-nonblock.h"
#include "crypto.h"

struct worker_state
{
  struct api_state api;
  int eof;
  int server_fd; /* server <-> worker bidirectional notification channel */
  int server_eof;
  sqlite3 *db;
  char lastReadTime[20];   //keeps track of which messages need ot be broadcasted to client
  char username[MAX_USR_LENGTH+1];
  int logged;
  SSL_CTX* ctx;
  SSL* ssl;
};

/**
 * @brief Reads an incoming notification from the server, queries
 *        the database for all unread notifications, and sends
 *        the client of all of the unread messages.
 */
static int handle_s2w_notification(struct worker_state *state)
{

  if(!state->logged)return 0;
  struct api_msg temp;
  sqlite3_stmt *stmt = NULL;
  char *msgPtr = NULL, *usrPtr= NULL, *tPtr= NULL;
  ssize_t res;
  int r = sqlite3_open("chat.db", &state->db);
  if (r)
  {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(state->db));
    sqlite3_close(state->db);
    return -1;
  }

  // create sql query to select all unread msgs

  char sql[] = "SELECT * FROM msg WHERE (msg_type=2) OR (msg_type=1 AND (receiver = ?1 OR sender= ?2))  group by id having timestamp > ?3";

  if (sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL) == SQLITE_OK)
  {
      if((r = sqlite3_bind_text(stmt, 1,state->username, -1, SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
      if((r = sqlite3_bind_text(stmt, 2,state->username, -1, SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
      //if((r = sqlite3_bind_int(stmt, 3, state->lastReadId)) != SQLITE_OK) goto cleanup;
      if((r = sqlite3_bind_text(stmt, 3, state->lastReadTime,-1,SQLITE_STATIC)) != SQLITE_OK) goto cleanup;

      while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        memset(&temp,0,sizeof(temp));
      //state->lastReadId = sqlite3_column_int(stmt, 0);
      tPtr = (char *)sqlite3_column_text(stmt, 1);
      strncpy(temp.time, tPtr, 20);

      strncpy(state->lastReadTime,temp.time, 20);
      //printf("lastReadTime: %s\n",state->lastReadTime);

      msgPtr = (char *)sqlite3_column_text(stmt, 2);
      temp.type = sqlite3_column_int(stmt, 5);
      if(temp.type == CMD_PUBLIC_MSG){
          strncpy(temp.publicMsg.message, msgPtr, strlen(msgPtr) + 1);
          usrPtr = (char *)sqlite3_column_text(stmt, 3);
          strncpy(temp.publicMsg.sender, usrPtr, strlen(usrPtr) + 1);
      } else{
          temp.privateMsg.len = sqlite3_column_int(stmt, 7);
          memcpy(temp.privateMsg.message, msgPtr, temp.privateMsg.len);
          usrPtr = (char *)sqlite3_column_text(stmt, 3);
          strncpy(temp.privateMsg.sender, usrPtr, strlen(usrPtr) + 1);
          usrPtr = (char *)sqlite3_column_text(stmt, 4);
          strncpy(temp.privateMsg.receiver, usrPtr, strlen(usrPtr) + 1);


      }
        memcpy(temp.sig,(unsigned char*)sqlite3_column_text(stmt, 6),SIG_LENGTH);
        usrPtr = NULL;
        tPtr = NULL;
        msgPtr = NULL;

      //send the message to client
      //res = write(state->api.fd, &temp, sizeof(temp));
      //res = send(state->api.fd,&temp,sizeof (temp) ,0);
        res = api_send(state->api.fd,&temp,state->ssl);
      if (res < 0 && errno != EPIPE)
      {
        perror("error: write failed");
          if(stmt)
              sqlite3_finalize(stmt);
          if(state->db)
              sqlite3_close(state->db);
        return -1;
      }
    }
  }
  else
    perror("error: reading from db failed\n");

  //clean up memory

    cleanup:
    if (r != SQLITE_OK && r != SQLITE_DONE)
        fprintf(stderr, "database error: %s\n", sqlite3_errmsg(state->db));
    if(stmt) sqlite3_finalize(stmt);
    if(state->db) sqlite3_close(state->db);
    return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused)) static int notify_workers(struct worker_state *state)
{

  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers, data does not matter */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE)
  {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(
    struct worker_state *state,
     struct api_msg *msg)
{
  /* TODO handle request and reply to client */
    switch (msg->type) {
        case CMD_PUBLIC_MSG:
            if(state->logged){
                //check message length
                if(!(check_length((char*)msg->publicMsg.message,2,MAX_MESSAGE_LENGTH))){
                    return send_response(state->api.fd,INVALID_MSG_LEN,NULL, state->ssl);
                    return 0;
                }
                //check sender's username matches
                if(strncmp(state->username,msg->publicMsg.sender,MAX_USR_LENGTH)!=0){
                    return send_response(state->api.fd,USER_DOES_NOT_MATCH,NULL, state->ssl);
                    return 0;
                }

                if(verify_sig(msg,msg->publicMsg.sender) != 0){
                    return send_response(state->api.fd,BAD_SIGNATURE,NULL, state->ssl);
                    return 0;
                }

                int res = insert_msg(state->db,(char*)msg->publicMsg.sender,"",(char*)msg->publicMsg.message,-1,CMD_PUBLIC_MSG, (char*)msg->sig);
                if(res == SQLITE_DONE){
                    notify_workers(state);
                    return 0;
                } else {
                    printf("could not insert message\n");
                    return -1;
                }
            } else {
                send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);
                return 0;
            }


        case CMD_PRIVATE_MSG:
            if(state->logged){

                if(!(check_length((char*)msg->privateMsg.message,2,MAX_MESSAGE_LENGTH))){
                    return send_response(state->api.fd,INVALID_MSG_LEN,NULL, state->ssl);
                    return 0;
                }
                if(!(valid_username((char*)msg->privateMsg.receiver,ALLOWED_USR_CHARS)) ){
                    return send_response(state->api.fd,USER_NOT_FOUND,NULL, state->ssl);
                }
                //check sender's username matches
                if(strncmp(state->username,msg->privateMsg.sender,MAX_USR_LENGTH)!=0){
                    send_response(state->api.fd,USER_DOES_NOT_MATCH,(char*)msg->keyExchange.sender, state->ssl);
                    return 0;
                }

                if(verify_sig(msg,msg->privateMsg.sender) != 0){
                    send_response(state->api.fd,BAD_SIGNATURE,(char*)msg->keyExchange.sender, state->ssl);
                    return 0;
                }


                int res = insert_msg(state->db,(char*)msg->privateMsg.sender,(char*)msg->privateMsg.receiver,(char*)msg->privateMsg.message,msg->privateMsg.len,CMD_PRIVATE_MSG, (char*)msg->sig);
                if(res == SQLITE_DONE){
                    notify_workers(state);
                    return 0;
                } else {
                    return send_response(state->api.fd,USER_NOT_FOUND,NULL, state->ssl);
                }
            } else {
                return send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);

            }
        case CMD_REGISTER:
            if(!state->logged){
                //check username and password meet the requirements
                if(!(check_length((char*)msg->auth.username,MIN_USR_LENGTH,MAX_USR_LENGTH))){
                    return send_response(state->api.fd,INVALID_USR_LEN,NULL, state->ssl);
                }
                if(!(valid_username((char*)msg->auth.username,ALLOWED_USR_CHARS))){
                    return send_response(state->api.fd,INVALID_CHR_IN_USR,NULL, state->ssl);
                }
                if(!(check_length((char*)msg->auth.password,MIN_PASS_LENGTH,SALT_LENGTH))){
                    return send_response(state->api.fd,INVALID_PSW_LEN,NULL, state->ssl);

                }
                //don't need to check if username already exists since there is a unique constraint for
                //the username. just check the returned value of the query

                //call functions to generate salt and hash the password
                unsigned char *salt = calloc(SALT_LENGTH,sizeof (unsigned char ));
                if(generate_salt(salt) != 0){
                    printf("error: could not generate salt\n");
                    free(salt);
                    send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);
                    return 0;
                }

                unsigned char *hash = calloc(SALT_LENGTH /*EVP_MD_size(EVP_sha256())*/ , sizeof(unsigned char));
                if(hash_salt_password(salt,hash,(char*)msg->auth.password) != 0){
                    printf("error: could not hash the password\n");
                    free(salt);
                    free(hash);
                    send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);
                    return 0;
                }


                //store salt and hash
                int res = register_user(state->db,(char*)msg->auth.username,hash,salt);

                //free salt and password
                free(salt);
                free (hash);


                //send result to client
                if(res == SQLITE_CONSTRAINT){
                    send_response(state->api.fd,USERNAME_EXISTS,(char*)msg->auth.username, state->ssl);
                    return 0;
                }
                else if(res == SQLITE_DONE){
                    strncpy(state->username,msg->auth.username,MAX_USR_LENGTH);
                    state->logged = 1;
                    set_user_status(state->db,state->username,1);
                    send_response(state->api.fd,REG_SUCCESSFUL,(char *)msg->auth.username, state->ssl);
                    handle_s2w_notification(state);
                    return 0;
                }
            } else return send_response(state->api.fd,ALREADY_LOGGED_IN,NULL, state->ssl);




        case CMD_LOGIN:
            if(!state->logged) {
                //check username and password meet the requirements
                if(!(valid_username((char*)msg->auth.username,ALLOWED_USR_CHARS)) || !(check_length((char*)msg->auth.password,MIN_PASS_LENGTH,SALT_LENGTH))){
                    send_response(state->api.fd,INVALID_USR_LEN,NULL, state->ssl);
                    return 0;
                }

                //get username,salt,hash from db if user exists
                unsigned char salt[SALT_LENGTH];
                unsigned char hash[SALT_LENGTH];
                memset(salt, 0, SALT_LENGTH);
                memset(hash, 0, SALT_LENGTH);
                int res = get_credentials(state->db,(char*)msg->auth.username,hash,salt);
                if(res == 1){
                    unsigned char *temp = calloc(EVP_MD_size(EVP_sha256()) , sizeof(unsigned char));
                    if(hash_salt_password(salt,temp,(char*)msg->auth.password) != 0){
                        printf("error: could not hash the password\n");
                        free(temp);
                        send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);
                        return 0;
                    }

                    //check if password is correct
                    if(memcmp(temp,hash,SALT_LENGTH) !=0) {
                        send_response(state->api.fd,INVALID_CREDENTIALS,NULL, state->ssl);
                        free(temp);
                        return 0;
                    }
                    free(temp);
                    //if login was successful:
                    strncpy(state->username,msg->auth.username,MAX_USR_LENGTH);
                    state->logged = 1;
                    if(set_user_status(state->db,(char *)msg->auth.username,1) == SQLITE_DONE){
                        send_response(state->api.fd,LOGIN_SUCCESSFUL,(char *)msg->auth.username, state->ssl);
                        handle_s2w_notification(state);
                        return 0;
                    } else {
                        printf("error in sql\n");
                        return -1;
                    }
                } else if (res == 0){
                    //user does not exist
                    send_response(state->api.fd,INVALID_CREDENTIALS,NULL, state->ssl);
                    return 0;
                } else{
                    //something went wrong in the db (should not happen?)
                    printf("db error\n");
                    return -1;
                }
            } else return send_response(state->api.fd,ALREADY_LOGGED_IN,NULL, state->ssl);

        case CMD_USERS:
            if(!state->logged) return send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);
            else {
                struct api_msg response;
                memset(&response,0,sizeof(struct api_msg));
                response.type=CMD_USERS;
                int res = get_users(state->db, &response);
                if (res == 0) {

                   //size_t r = write(state->api.fd, &response, sizeof(struct api_msg));
                   ssize_t r = api_send(state->api.fd,&response,state->ssl);
                   if (r < 0 && errno != EPIPE) {
                        perror("error: write failed");
                    }
                } else {
                    printf("Error executing sql statement\n");
                    return -1;
                }
                return 0;
            }

        case AES_KEY_INSERT:
            if(state->logged){
                if(!(check_length((char*)msg->keyExchange.key,2,MAX_MESSAGE_LENGTH))){
                    send_response(state->api.fd,INVALID_MSG_LEN,NULL, state->ssl);
                    return 0;
                }
                if(!(check_length((char*)msg->keyExchange.receiver,MIN_USR_LENGTH,MAX_USR_LENGTH)) ){
                    return send_response(state->api.fd,USER_NOT_FOUND,NULL, state->ssl);
                }
                //check sender's username matches
                if((strncmp(state->username,msg->keyExchange.sender,MAX_USR_LENGTH)!=0) && (strncmp(state->username,msg->keyExchange.receiver,MAX_USR_LENGTH) != 0)){
                    send_response(state->api.fd,USER_DOES_NOT_MATCH,(char*)msg->keyExchange.sender, state->ssl);
                    return 0;
                }
                int res;
                if(strncmp(state->username,msg->keyExchange.sender,MAX_USR_LENGTH) == 0){
                    res = verify_sig(msg,msg->keyExchange.sender);
                } else{
                    res = verify_sig(msg,msg->keyExchange.receiver);
                }
                if(res != 0){
                    return send_response(state->api.fd,BAD_SIGNATURE,NULL, state->ssl);
                    return 0;
                }

                res = insert_key(state->db,(char*)msg->keyExchange.sender,(char*)msg->keyExchange.receiver,(char*)msg->keyExchange.key,msg->keyExchange.keyLen,(char*)msg->keyExchange.iv,(char*)msg->sig);
                if(res == SQLITE_DONE){
                    //notify_workers(state);
                    //printf("aes key added successfully.\n");
                    send_response(state->api.fd,KEY_INSERT_SUCCESSFUL,(char*)msg->keyExchange.receiver, state->ssl);
                    return 0;
                } else if(res == SQLITE_CONSTRAINT){
                    //printf("key-constraint\n");
                    send_response(state->api.fd,KEY_ALREADY_EXISTS,(char*)msg->keyExchange.receiver, state->ssl);
                    return 0;
                } else
                    return send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);

            } else {
                return send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);

            }
        case AES_KEY_REQUEST:
            if(state->logged){
                if(!(check_length((char*)msg->keyExchange.receiver,MIN_USR_LENGTH,MAX_USR_LENGTH)) ){
                    return send_response(state->api.fd,USER_NOT_FOUND,NULL, state->ssl);
                }
                //check sender's username matches
                if(strncmp(state->username,msg->keyExchange.sender,MAX_USR_LENGTH)!=0){
                    send_response(state->api.fd,USER_DOES_NOT_MATCH,(char*)msg->keyExchange.sender, state->ssl);
                    return 0;
                }

                if(verify_sig(msg,msg->keyExchange.sender) != 0){
                    return send_response(state->api.fd,BAD_SIGNATURE,NULL, state->ssl);
                    return 0;
                }

                char key[RSA_KEY_SIZE],iv[IV_LEN],sig[SIG_LENGTH];
                memset(key,0,RSA_KEY_SIZE);
                memset(iv,0,IV_LEN);
                int res = get_key(state->db,msg->keyExchange.sender,msg->keyExchange.receiver,(char*)key,(char*)iv, (char*)sig);
                if(res == 0){
                    send_response(state->api.fd,KEY_NOT_FOUND,(char*)msg->keyExchange.receiver, state->ssl);
                    return 0;
                } else{
                    //send the key
                    struct api_msg temp;
                    memset(&temp, 0, sizeof(temp));
                    temp.type = AES_KEY_REQUEST;
                    memcpy(temp.keyExchange.receiver,msg->keyExchange.sender,MAX_USR_LENGTH);
                    memcpy(temp.keyExchange.sender,msg->keyExchange.receiver,MAX_USR_LENGTH);
                    memcpy(temp.keyExchange.iv, iv, IV_LEN);
                    memcpy(temp.keyExchange.key, key, RSA_KEY_SIZE);
                    memcpy(temp.sig,sig,SIG_LENGTH);
                    temp.keyExchange.keyLen = RSA_KEY_SIZE;
                    api_send(state->api.fd,&temp,state->ssl);
                    return 0;
                }

            } else {
                return send_response(state->api.fd,CMD_NOT_AVAILABLE,NULL, state->ssl);

            }
        case SERVER_RESPONSE:
            //should not happen?
        default:
            return -1;
    }
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state)
{
  struct api_msg msg;
  int r, success = 1;
  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg, state->ssl);
  if (r < 0)
  {
    return -1;
  }
  if (r == 0){
    state->eof = 1;
    return 0;
  }
  /* execute request */
  if (execute_request(state, &msg) != 0)
  {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);

  return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state)
{
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
  * about new messages; these notifications are idempotent so the number
  * does not actually matter, nor does the data sent over the pipe
  */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0)
  {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0)
  {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0)
    return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state)
{
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof)
  {
    FD_SET(state->server_fd, &readfds);
  }
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
  if (r < 0)
  {
    if (errno == EINTR)
      return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /*  TODO once you implement encryption you may need to call ssl_has_data
  *   here due to buffering (see ssl-nonblock example)
  */

  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->ssl))
  {
    if (handle_client_request(state) != 0)
      success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds))
  {
    if (handle_s2w_read(state) != 0)
      success = 0;
  }
  return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(
    struct worker_state *state,
    int connfd,
    int server_fd,
    sqlite3 *db)
{

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd);

  /* TODO any additional worker state initialization */
  state->db = db;
  //state->lastReadId = 0;
  memset(state->lastReadTime,0,20);

  /* configure SSL */
  state->ctx = SSL_CTX_new(TLS_server_method());
  if(state->ctx == NULL){
    printf("creation of a new SSL_CTX object failed\n");
    return 1;
  }
  state->ssl = SSL_new(state->ctx);
  if(state->ssl == NULL){
      printf("failed to create ssl structure\n");
      return 1;
  }
  SSL_use_certificate_file(state->ssl, PATHCERT, SSL_FILETYPE_PEM);
  SSL_use_PrivateKey_file(state->ssl, PATHKEY, SSL_FILETYPE_PEM);

  /* set up SSL connection with client */

  if(set_nonblock(connfd) != 0){
    printf("set_nonblock failed\n");
    return 1;
  }

  if(SSL_set_fd(state->ssl, connfd) != 1){
    printf("setting ssl fd failed\n");
    return 1;
  }
  if(ssl_block_accept(state->ssl, connfd) == -1){
      printf("ssl_block_accept failed\n");
      return 1;
  }


  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
    struct worker_state *state)
{
  /* clean up SSL */
  if(state->ssl) SSL_free(state->ssl);
  if(state->ctx) SSL_CTX_free(state->ctx);

  /* clean up API state */
  api_state_free(&state->api);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 * @param db           Database reference
 */
__attribute__((noreturn)) void worker_start(
    int connfd,
    int server_fd,
    sqlite3 *db)
{
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd, db) != 0)
  {
    goto cleanup;
  }

  //handle_s2w_notification(&state);

  /* handle for incoming requests */
  while (!state.eof)
  {
    if (handle_incoming(&state) != 0)
    {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  /* TODO any additional worker cleanup */

  set_user_status(state.db,state.username,0);

  worker_state_free(&state);

  exit(success ? 0 : 1);
}
