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

struct client_state
{
  struct api_state api;
  int eof;
  struct ui_state ui;
  /* TODO client state variables go here */
  int logged;
  char username[MAX_USR_LENGTH+1];
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
        memset(&msg, 0, sizeof(msg));
        msg.type = CMD_PRIVATE_MSG;
        memcpy(msg.privateMsg.sender,state->username,MAX_USR_LENGTH);
        memcpy(msg.privateMsg.message, temp, strlen(temp) + 1);
        memcpy(msg.privateMsg.receiver, receiver, recUsrLen);
        return (api_send(state->api.fd,&msg));


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
              printf("%s","error: command not currently available\n");
              return 0;
            }

          temp = remove_leading_space(&temp[6], strlen(temp)-6);
          if (isspace(*temp)){
              printf("error: invalid command format\n");
              return 0;
          }
          state->ui.cmd = CMD_LOGIN;
          if(get_credential(temp,&state->ui) == 1){
              struct api_msg msg;
              memset(&msg, 0, sizeof(msg));
              msg.type = CMD_LOGIN;


              //TODO: do the crypto stuff here
              //TODO: is it safe/necessary to store password after logging in?? (ask)

              //printf("username: %s\n",state->ui.username);
              //printf("password: %s\n",state->ui.password);
              strncpy(msg.auth.username,state->ui.username,MAX_USR_LENGTH);
              strncpy(msg.auth.password,state->ui.password,MAX_PASS_LENGTH);


              return (api_send(state->api.fd,&msg));

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
            printf("%s", "error: invalid command format\n");
            return 0;
          }
        }
      case 'r':
        if (strncmp(temp, "/register", 9) == 0)
        {
            if(isalnum( (temp[9])))goto unknown;

            if(state->logged == 1){
                //already logged in
                printf("%s","error: command not currently available\n");
                return 0;
            }

            state->ui.cmd = CMD_REGISTER;
            temp = remove_leading_space(&temp[9], strlen(temp)-9);
            if (isspace(*temp)){
                printf("error: invalid command format\n");
                return 0;
            }

            if(get_credential(temp,&state->ui) == 1){
                //TODO: encryption stuff

                struct api_msg msg;
                memset(&msg, 0, sizeof(msg));
                msg.type = CMD_REGISTER;
                strncpy(msg.auth.username,state->ui.username,MAX_USR_LENGTH);
                strncpy(msg.auth.password,state->ui.password,MAX_PASS_LENGTH);
                return (api_send(state->api.fd,&msg));

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
                printf("%s","error: command not currently available\n");
                return 0;
              } else{
                  struct api_msg msg;
                  memset(&msg, 0, sizeof(msg));
                  msg.type = CMD_USERS;
                  return (api_send(state->api.fd,&msg));
              }

          }
          else
          {
            printf("%s", "error: invalid command format\n");
            return 0;
          }
        }
        //TODO: is this vulnerable????
      unknown:
      default:
        printf("error: unknown command %s",temp);
        return 0;
      }
    } else {

        remove_trailing_space(temp, strlen(temp));
        state->ui.cmd = CMD_PUBLIC_MSG;

        struct api_msg msg;
        memset(&msg, 0, sizeof(msg));
        memcpy(msg.publicMsg.sender,state->username,MAX_USR_LENGTH);
        memcpy(msg.publicMsg.message, temp, strlen(temp) + 1);
        msg.type = CMD_PUBLIC_MSG;


        return (api_send(state->api.fd,&msg));
    }
  }

    // ./client localhost 8081 < <(python3 -c "print('hiiiiiiii')")
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
    const struct api_msg *msg)
{
  if (msg->type == CMD_PUBLIC_MSG)
  {
    //const struct public_msg *temp =  &msg->publicMsg;
    //printf("%s %s: %s", msg->time, temp->sender, temp->message);

    //TODO: verify the signature here?? is it needed if server is verified?

    printf("%s %s: %s", msg->time, msg->publicMsg.sender, msg->publicMsg.message);
  } else if(msg->type == CMD_PRIVATE_MSG){
      printf("%s %s: @%s %s", msg->time, msg->privateMsg.sender,msg->privateMsg.receiver, msg->privateMsg.message);
  } else if(msg->type == SERVER_RESPONSE){
      switch (msg->serverResponse.response) {
          case REG_SUCCESSFUL:
              strncpy(state->username,msg->serverResponse.message,MAX_USR_LENGTH);
              state->logged=1;
              printf("registration succeeded\n");
              return 0;
          case LOGIN_SUCCESSFUL:
              strncpy(state->username,msg->serverResponse.message,MAX_USR_LENGTH);
              state->logged=1;
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
      }
  } else if (msg->type == CMD_USERS){
      //todo: add more sanitization checks
      for(int i=0;i<msg->users.num_users;i++){
          if(!(check_length((char*)msg->users.users[i],MIN_USR_LENGTH,MAX_USR_LENGTH)))return -1;
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
  r = api_recv(&state->api, &msg);

  if (r < 0)
  {
    printf("r<0\n");
    return -1;
  }
  if (r == 0)
  {
    printf("r==0\n");
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
  if (FD_ISSET(state->api.fd, &readfds))
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

  //already set to 0 by memset?
  state->logged = 0;

    return 0;
}

static void client_state_free(struct client_state *state)
{

  /* TODO any additional client state cleanup */

  /* cleanup API state */
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);

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

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0)
    ;

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}
