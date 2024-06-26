#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include "api.h"
#include "ui.h"
#include "util.h"

#include <openssl/ssl.h>
#include "ssl-nonblock.h"
#include "crypto.h"
#include "ttp.h"

struct client_state
{
  struct api_state api;
  int eof;
  struct ui_state ui;
  /* TODO client state variables go here */
  int logged;
  char username[MAX_USR_LENGTH+1];
  SSL_CTX *ctx;
  SSL *ssl;
  EVP_PKEY *evpKey;
  LinkedList *decList;
  LinkedList *encList;
};

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
                          const char *hostname, uint16_t port)
{
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);

  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0)
    return -1;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* connect to server */
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    perror("error: cannot connect to server");
    close(fd);
    return -1;
  }

  return fd;
}

static int client_process_command(struct client_state *state)
{
  assert(state);

  char *buffer = state->ui.message;
  memset(state->ui.message, 0, sizeof (*state->ui.message));
  //read stdin
  if (fgets(buffer, MAX_MESSAGE_LENGTH, stdin) != NULL)
  {
    size_t len = strlen(buffer);
    //set eof
    if(feof(stdin)){
        state->eof = 1;
    }
    if(len < 2){
        printf("error: no command was entered!\n");
        return 0;
    }
    //check if input is truncated
    if ((buffer[len - 1] != '\n') && !feof(stdin))
    {
      printf("error: input exceed max limit!\n");
      flush_stdin();
      return 0;
    }

    //check only one newline exists
    if (new_line_count(buffer) != 1)
    {
        printf("%s","error: invalid command format\n");
        return 0;
    }

    char *temp = buffer;
    temp = remove_leading_space(temp, len);
    if (strlen(temp) < 2)
    {
        printf("%s","error: invalid command format\n");
        return 0;
    }

    if(temp[0] == '@'){
        if(state->logged == 0){
            printf("%s","error: command not currently available\n");
            return 0;
        }
        if(isspace(temp[1])){
            printf("error: invalid command format\n");
            return 0;
        }
        temp++;
        char receiver[MAX_USR_LENGTH+1]={'\0'};
        int recUsrLen = 0;
        while(!isspace(temp[recUsrLen])){
            receiver[recUsrLen] = temp[recUsrLen];
            recUsrLen++;
            if(recUsrLen > MAX_USR_LENGTH){
                printf("error: username exceeded maximum length\n");
                return 0;
            }
        }

        temp+=recUsrLen;
        temp = remove_leading_space(temp, strlen(temp));

        if (strlen(temp) < 2)
        {
            printf("%s","error: invalid command format\n");
            return 0;
        }

        remove_trailing_space(temp, strlen(temp));
        state->ui.cmd = CMD_PRIVATE_MSG;
        struct api_msg msg;
        memset(&msg, 0, sizeof(struct api_msg));
        msg.type = CMD_PRIVATE_MSG;
        memcpy(msg.privateMsg.sender,state->username,MAX_USR_LENGTH);
        memcpy(msg.privateMsg.message, temp, strlen(temp) + 1);
        memcpy(msg.privateMsg.receiver, receiver, recUsrLen);


        unsigned char *outbuff = calloc(1, MAX_MESSAGE_LENGTH+1);
        int encLen;
        int r = aes_enc(msg.privateMsg.sender,state->ui.password,msg.privateMsg.receiver,(unsigned char*)msg.privateMsg.message,outbuff,&encLen);
        if(r == 1){
            //key does not exist
            if(receiver_exists(msg.privateMsg.receiver)){
                if(strcmp(msg.privateMsg.receiver,state->username) == 0){
                    // generate AES key (when we are messaging ourself)
                    printf("generating AES key for ourself\n");
                    r = generate_symm_key(state->username,state->ui.password,msg.privateMsg.receiver);
                    if(r == 0){
                        if(send_key(state->api.fd,msg.privateMsg.sender,state->ui.password,msg.privateMsg.receiver,state->ssl,state->evpKey,NULL,NULL) != 0){
                            return 0;
                        }
                        aes_enc(msg.privateMsg.sender,state->ui.password,msg.privateMsg.receiver,(unsigned char*)msg.privateMsg.message,outbuff,&encLen);
                    } else{
                        //could not generate aes key (error is already printed)
                        return 0;
                    }
                } else{
                    //add msg to encryption list
                    struct api_msg *temp = calloc(1, sizeof(struct api_msg));
                    memcpy(temp, &msg, sizeof(struct api_msg));
                    //send key request to the server if not sent already
                    if(get_node(state->encList,temp->privateMsg.receiver) == NULL){
                        request_key(state->api.fd,temp->privateMsg.sender,temp->privateMsg.receiver,state->ssl,state->evpKey);
                    } else printf("already sent a key request for user '%s'. adding it to the list.\n",msg.privateMsg.receiver);

                    insert_node(state->encList,temp);
                    //print_list(state->encList);
                    free(outbuff);
                    return 0;
                }

            } else {
                //receiver does not exist
                printf("error: user not found\n");
                free(outbuff);
                return 0;
            }
        } else if(r != 0) return 0;

        memset(&msg.privateMsg.message, 0, sizeof(msg.privateMsg.message));
        memcpy(&msg.privateMsg.message, outbuff, sizeof(msg.privateMsg.message));
        msg.privateMsg.len = encLen;
        free(outbuff);

        sign(&msg,state->evpKey);
        return (api_send(state->api.fd,&msg,state->ssl));


    }
    else if (temp[0] == '/')
    {
      switch (temp[1])
      {
      case 'l':
        if (strncmp(temp, "/login", 6) == 0)
        {

          if(isalnum( (temp[6]))){
              int i = 6;
              while(!isspace(temp[i])){
                  if(i >MAX_MESSAGE_LENGTH) return -1;
                  i++;
              }
              temp[i] = '\n';
              temp[i+1]='\0';
              goto unknown;
          }

          if(state->logged == 1){
              //already logged in
              printf("error: command not currently available\n");
              return 0;
            }

          temp = remove_leading_space(&temp[6], strlen(temp)-6);
          if (isspace(*temp)){
              printf("error: invalid command format\n");
              return 0;
          }
          state->ui.cmd = CMD_LOGIN;
          if((get_credential(temp,&state->ui) == 1) && valid_username(state->ui.username,ALLOWED_USR_CHARS)){
              struct api_msg msg;
              memset(&msg, 0, sizeof(msg));
              msg.type = CMD_LOGIN;
              strncpy(msg.auth.username,state->ui.username,MAX_USR_LENGTH);
              unsigned char *hash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
              if(hash_password(hash,state->ui.password) != 0){
                  free(hash);
                  printf("could not hash user's password.\n");
                  return 0;
              }
              memcpy(msg.auth.password,hash,SHA256_HASH_SIZE);
              free(hash);
              return (api_send(state->api.fd,&msg,state->ssl));

              return 0;
            }



          return 0;
        }
      case 'e':
        if (strncmp(temp, "/exit", 5) == 0)
        {
          temp += 5;
          if (!isspace(*temp)) {
              temp -= 5;
              goto unknown;
          }

          temp = remove_leading_space(temp, strlen(temp));
          if (temp[0] == '\n')
          {
              state->eof = 1;
              return 0;
          }
          else
          {
            printf("error: invalid command format\n");
            return 0;
          }
        }
      case 'r':
        if (strncmp(temp, "/register", 9) == 0)
        {
            if(isalnum( (temp[9])))goto unknown;

            if(state->logged == 1){
                //already logged in
                printf("error: command not currently available\n");
                return 0;
            }

            state->ui.cmd = CMD_REGISTER;
            temp = remove_leading_space(&temp[9], strlen(temp)-9);
            if (isspace(*temp)){
                printf("error: invalid command format\n");
                return 0;
            }

            if((get_credential(temp,&state->ui) == 1) && valid_username(state->ui.username,ALLOWED_USR_CHARS)){
                struct api_msg msg;
                memset(&msg, 0, sizeof(msg));
                msg.type = CMD_REGISTER;
                strncpy(msg.auth.username,state->ui.username,MAX_USR_LENGTH);
                unsigned char *hash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
                if(hash_password(hash,state->ui.password) != 0){
                    free(hash);
                    printf("could not hash user's password.\n");
                    return 0;
                }
                memcpy(msg.auth.password,hash,SHA256_HASH_SIZE);
                free(hash);
                return (api_send(state->api.fd,&msg,state->ssl));

            }

            return 0;
        }
      case 'u':
        if (strncmp(temp, "/users", 6) == 0)
        {
          temp += 6;
          if (!isspace(*temp)){
              temp -= 6;
              goto unknown;
          }

          temp = remove_leading_space(temp, strlen(temp));
          if (temp[0] == '\n')
          {

              if(state->logged == 0){
                printf("error: command not currently available\n");
                return 0;
              } else{
                  struct api_msg msg;
                  memset(&msg, 0, sizeof(msg));
                  msg.type = CMD_USERS;
                  return (api_send(state->api.fd,&msg,state->ssl));
              }

          }
          else
          {
            printf("error: invalid command format\n");
            return 0;
          }
        }

      unknown:
      default:
        fprintf(stdout,"error: unknown command %s",temp);
        return 0;
      }
    } else {
        if(state->logged == 0){
            printf("%s","error: command not currently available\n");
            return 0;
        }
        remove_trailing_space(temp, strlen(temp));
        state->ui.cmd = CMD_PUBLIC_MSG;

        struct api_msg msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = CMD_PUBLIC_MSG;
        memcpy(msg.publicMsg.sender,state->username,MAX_USR_LENGTH);
        memcpy(msg.publicMsg.message, temp, strlen(temp) + 1);

        sign(&msg,state->evpKey);

        return (api_send(state->api.fd,&msg,state->ssl));
    }
  }

  if(feof(stdin))
      state->eof = 1;

  return -1;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
    struct client_state *state,
     struct api_msg *msg)
{
  if (msg->type == CMD_PUBLIC_MSG)
  {
    if(verify_sig(msg,msg->publicMsg.sender) != 0){
        printf("signature for received message is incorrect. dropping...\n");
        return 0;
    }
    printf("%s %s: %s", msg->time, msg->publicMsg.sender, msg->publicMsg.message);
  } else if(msg->type == CMD_PRIVATE_MSG){
      if(verify_sig(msg,msg->privateMsg.sender) != 0){
          printf("signature for received message is incorrect. dropping...\n");
          printHex(SIG_LENGTH,msg->sig);
          return 0;
      }
      unsigned char *out = calloc(1, MAX_MESSAGE_LENGTH);
      int r;
      if(strcmp(msg->privateMsg.sender,state->ui.username) == 0){
         r = aes_dec(msg->privateMsg.sender,state->ui.password,msg->privateMsg.receiver,(unsigned char*)msg->privateMsg.message,out,&msg->privateMsg.len);
      } else{
         r = aes_dec(msg->privateMsg.receiver,state->ui.password,msg->privateMsg.sender,(unsigned char*)msg->privateMsg.message,out,&msg->privateMsg.len);
      }
      if(r == 0){
        printf("%s %s: @%s %s", msg->time, msg->privateMsg.sender,msg->privateMsg.receiver, out);
        free(out);
        return 0;
      } else {
          //printf("could not decrypt private msg from %s.\nmsg added to decrypt list...\n",msg->privateMsg.sender);
          struct api_msg *temp = calloc(1, sizeof(struct api_msg));
          memcpy(temp, msg, sizeof(struct api_msg));

          //send key request to the server if not sent already
          if(!waiting_for_key(state->decList,msg->privateMsg.receiver)){
              if(strcmp(msg->privateMsg.sender,state->ui.username) == 0){
                  request_key(state->api.fd,msg->privateMsg.sender,msg->privateMsg.receiver,state->ssl,state->evpKey);
              } else {
                  request_key(state->api.fd, msg->privateMsg.receiver, msg->privateMsg.sender, state->ssl, state->evpKey);
              }
          }

          insert_node(state->decList,temp);
          //print_list(state->decList);
          free(out);
          return 0;
      }

  } else if(msg->type == AES_KEY_REQUEST){
      //verifying the key
      struct api_msg temp;
      memset(&temp,0, sizeof(temp));
      memcpy(&temp,msg, sizeof(*msg));
      temp.type = AES_KEY_INSERT;
      memset(&temp.keyExchange.sender,0,MAX_USR_LENGTH+1);
      memset(&temp.keyExchange.receiver,0,MAX_USR_LENGTH+1);
      memcpy(&temp.keyExchange.sender,msg->keyExchange.receiver,MAX_USR_LENGTH+1);
      memcpy(&temp.keyExchange.receiver,msg->keyExchange.sender,MAX_USR_LENGTH+1);


      if((verify_sig(&temp,temp.keyExchange.sender) != 0) && (verify_sig(&temp,temp.keyExchange.receiver))){
          printf("signature for received AES is incorrect.\ndropping %d messages from user '%s'\n",remove_msgs_from_user(state->decList,msg->keyExchange.sender),msg->keyExchange.sender);
          return 0;
      }
      unsigned char *plaintext = NULL;
      //decrypt the received key
      if(rsa_dec(state->evpKey,(unsigned char*)msg->keyExchange.key,&plaintext) == 0){
          //store key/iv in user's key directory
        if(write_aes_key(msg->keyExchange.receiver,state->ui.password,msg->keyExchange.sender,plaintext, msg->keyExchange.iv) != -1){
            //decrypt queued private messages from this sender
           // printf("decrypted %d queued messages from user '%s'.\n",dec_msgs_from_user(state->decList,msg->keyExchange.receiver,msg->keyExchange.sender,state->ui.password),msg->keyExchange.receiver);
          //  printf("encrypted and sent %d queued messages to user '%s'.\n", send_queued_msgs_to_user(state->encList,msg->keyExchange.sender,msg->keyExchange.receiver,state->ui.password,state->api.fd,state->ssl, state->evpKey),msg->keyExchange.receiver);
            dec_msgs_from_user(state->decList,msg->keyExchange.receiver,msg->keyExchange.sender,state->ui.password);
            send_queued_msgs_to_user(state->encList,msg->keyExchange.sender,msg->keyExchange.receiver,state->ui.password,state->api.fd,state->ssl, state->evpKey);

        }

          } else{
          printf("could not decrypt aes key\ndropping %d messages from '%s'\n",remove_msgs_from_user(state->decList,msg->keyExchange.sender),msg->keyExchange.sender);
          if(plaintext) free(plaintext);
          return 0;
      }
      if(plaintext) free(plaintext);
      return 0;

  } else if(msg->type == SERVER_RESPONSE){
      switch (msg->serverResponse.response) {
          case REG_SUCCESSFUL:
              strncpy(state->username,msg->serverResponse.message,MAX_USR_LENGTH);
              state->logged=1;
              printf("registration succeeded\n");
              //if(gen_rsa(state->ui.username,state->ui.password) != -1){
              if(gen_csr(state->ui.username,state->ui.password) != -1){
                  printf("sending csr to ttp\n");
                  if(sign_csr(state->ui.username,state->ui.password) == 0){
                      printf("certificate generated\n");
                      if(get_priv_key(state->evpKey,state->ui.username,state->ui.password) != 0){
                          printf("could not get our private key from key folder\n");
                          return 1;
                      }
                  }

              }
              else{
                  printf("could not generate rsa keys\n");
                  return 1;
                  }
              return 0;
          case LOGIN_SUCCESSFUL:
              strncpy(state->username,msg->serverResponse.message,MAX_USR_LENGTH);
              state->logged=1;
              //get the private key
              if(get_priv_key(state->evpKey,state->ui.username,state->ui.password) != 0){
                  printf("could not get private key\n");
                  return 1;
              }
              printf("authentication succeeded\n");
              return 0;
          case INVALID_CREDENTIALS:
              printf("error: invalid credentials\n");
              return 0;
          case CMD_NOT_AVAILABLE:
              printf("error: command not currently available\n");
              return 0;
          case USER_NOT_FOUND:
              printf("error: user not found\n");
              return 0;
          case USERNAME_EXISTS:
              if(check_length((char*)msg->serverResponse.message,MIN_USR_LENGTH,MAX_USR_LENGTH))
                  printf("error: user %s already exists\n",msg->serverResponse.message);
              return 0;
          case INVALID_CMD_FORMAT:
              printf("error: invalid command format\n");
              return 0;
          case INVALID_USR_LEN:
              printf("error: username does not meet required length\n");
              return 0;
          case INVALID_PSW_LEN:
              printf("error: password does not meet required length\n");
              return 0;
          case ALREADY_LOGGED_IN:
              printf("error: command not currently available\n");
              return 0;
          case KEY_ALREADY_EXISTS:
              if(check_length((char*)msg->serverResponse.message,MIN_USR_LENGTH,MAX_USR_LENGTH))
                  printf("server response: AES key for user '%s' already exists\n",msg->serverResponse.message);
              return 0;
          case KEY_NOT_FOUND:
              if(check_length((char*)msg->serverResponse.message,MIN_USR_LENGTH,MAX_USR_LENGTH)){
                  if((strcmp(msg->serverResponse.message,state->username) != 0) ||((strcmp(msg->serverResponse.message,state->username) == 0) && (waiting_for_key(state->decList,state->username)) )) {
                      //printf("server response:: AES key for user '%s' was not found in the database\n",msg->serverResponse.message);
                      printf("generating AES key for user '%s'\n", msg->serverResponse.message);
                      // generate AES key
                      unsigned char key[SYMM_KEY_LEN], iv[(IV_LEN)];
                      memset(key, 0, SYMM_KEY_LEN);
                      memset(iv, 0, IV_LEN);
                      int r = generate_symm_key_not_stored(state->username, msg->serverResponse.message, (unsigned char *) key, (unsigned char *) iv);
                      if (r == 0) {
                          if (send_key(state->api.fd, state->username, state->ui.password, msg->serverResponse.message, state->ssl, state->evpKey, (unsigned char *) key, (unsigned char *) iv) != 0) {
                              printf("sent aes-key-insert req to server for user '%s'\n", msg->serverResponse.message);
                              return 0;
                          }
                      }
              }
              }
              return 0;
          case KEY_INSERT_SUCCESSFUL:
              if(check_length((char*)msg->serverResponse.message,MIN_USR_LENGTH,MAX_USR_LENGTH)){
                  //printf("AES key for user '%s' added to the database\n",msg->serverResponse.message);
                  request_key(state->api.fd,state->username,msg->serverResponse.message,state->ssl,state->evpKey);
              }

              return 0;
          case USER_DOES_NOT_MATCH:
              if(check_length((char*)msg->serverResponse.message,MIN_USR_LENGTH,MAX_USR_LENGTH))
                  printf("user '%s' does not match the current user\n",msg->serverResponse.message);
              return 0;
          case INVALID_MSG_LEN:
              printf("error: invalid message length\n");
              return 0;
          case BAD_SIGNATURE:
              printf("error: message sent to server had bad signature\n");
              return 0;
          case INVALID_CHR_IN_USR:
              printf("error: username contains illegal characters\n");
              return 0;
      }
  } else if (msg->type == CMD_USERS){
      for(int i=0;i<msg->users.num_users;i++){
          if(!(valid_username((char*)msg->users.users[i],ALLOWED_USR_CHARS))){
              printf("received invalid username from server for users command.\n");
              return 0;
          }
          printf("%s\n",msg->users.users[i]);
      }
  }

  return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state)
{
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg,state->ssl);

  if (r < 0)
  {
    return -1;
  }
  if (r == 0)
  {
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

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state)
{
  int fdmax, r;
  fd_set readfds;

  assert(state);

  /* TODO if we have work queued up, this might be a good time to do it */

  /* TODO ask user for input if needed */

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

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
  if (FD_ISSET(STDIN_FILENO, &readfds))
  {
    return client_process_command(state);
  }
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */

  /*
  if (FD_ISSET(state->api.fd, &readfds))
  {
    return handle_server_request(state);
  }
  */

  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->ssl))
  {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state *state)
{
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  /* TODO any additional client state initialization */

  state->evpKey = EVP_PKEY_new();
  if(!state->evpKey){
      printf("could not allocate EVP_PKEY structure\n");
      return 1;
  }
  state->decList = init_list();
  state->encList = init_list();
  //already set to 0 by memset?
  state->logged = 0;

    return 0;
}

static void client_state_free(struct client_state *state){
    /* TODO any additional client state cleanup */
    /* clean up SSL */
    SSL_free(state->ssl);
    SSL_CTX_free(state->ctx);

    if (state->evpKey)
        EVP_PKEY_free(state->evpKey);

    /* cleanup API state */
    api_state_free(&state->api);

    /* cleanup UI state */
    ui_state_free(&state->ui);
    list_free(state->decList);
    if(state->decList) free(state->decList);
    list_free(state->encList);
    if(state->encList) free(state->encList);

    memset(state, 0, sizeof(*state));
}

static void usage(void)
{
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  int fd;
  uint16_t port;
  struct client_state state;

  /* check arguments */
  if (argc != 3)
    usage();
  if (parse_port(argv[2], &port) != 0)
    usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0)
    return 1;

  /* initialize API */
  api_state_init(&state.api, fd);

  /* TODO any additional client initialization */

  //TODO: add goto cleanup, and use error stack to print the error
  /* configure SSL */
    state.ctx = SSL_CTX_new(TLS_client_method());
    if(state.ctx == NULL){
        printf("creation of a new SSL_CTX object failed\n");
        return 1;
    }
    if(SSL_CTX_load_verify_locations(state.ctx,"clientkeys/ca-cert.pem" , NULL) != 1){
        printf("SSL_CTX_load_verify_locations failed\n");
        return 1;
    }
    state.ssl = SSL_new(state.ctx);
    if(state.ssl == NULL){
        printf("failed to create ssl structure\n");
        return 1;
    }
    SSL_set_verify(state.ssl, SSL_VERIFY_PEER, NULL);




  /* configure the socket as non-blocking */
   if(set_nonblock(fd) != 0){
       printf("set_nonblock failed\n");
       return 1;
   }

  /* set up SSL connection with client */
    if(SSL_set_fd(state.ssl, fd) != 1){
        printf("setting ssl fd failed\n");
        return 1;
    }
    if(ssl_block_connect(state.ssl, fd) == -1){
        printf("ssl_block_connect failed\n");
        return 1;
    }

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0)
    ;

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}
