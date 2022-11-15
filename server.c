#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sqlite3.h>

#include "util.h"
#include "worker.h"

#define MAX_CHILDREN 16

struct server_child_state
{
  int worker_fd; /* server <-> worker bidirectional notification channel */
  int pending;   /* notification pending yes/no */
};

struct server_state
{
  int sockfd;
  struct server_child_state children[MAX_CHILDREN];
  int child_count;
  sqlite3 *db;
};

static int create_server_socket(uint16_t port)
{
  int fd;
  struct sockaddr_in addr;

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* bind socket to specified port on all interfaces */
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    perror("error: cannot bind server socket to port");
    goto error;
  }

  /* start listening for incoming client connections */
  if (listen(fd, 0) != 0)
  {
    perror("error: cannot listen on server socket");
    goto error;
  }

  return fd;

error:
  close(fd);
  return -1;
}

static void child_add(struct server_state *state, int worker_fd)
{
  int i;

  assert(state);
  assert(worker_fd >= 0);

  /* store worker_fd */
  for (i = 0; i < MAX_CHILDREN; i++)
  {
    if (state->children[i].worker_fd < 0)
    {
      state->children[i].worker_fd = worker_fd;
      state->children[i].pending = 0;
      state->child_count++;
      return;
    }
  }

  fprintf(stderr, "error: children and child_count are inconsistent\n");
  abort();
}

static void children_check(struct server_state *state)
{
  pid_t pid;
  int status;

  assert(state);

  /* check for children that may have finished */
  for (;;)
  {
    /* check whether a child has finished */
    pid = waitpid(0, &status, WNOHANG);
    if (pid == -1 && errno != ECHILD && errno != EINTR)
    {
      perror("error: waitpid failed");
      abort();
    }
    if (pid == 0 || pid == -1)
    {
      /* no children exited */
      break;
    }

    /* report how the child died */
    if (WIFSIGNALED(status))
    {
      fprintf(stderr, "warning: child killed by signal %d\n", WTERMSIG(status));
    }
    else if (!WIFEXITED(status))
    {
      fprintf(stderr, "warning: child died of unknown causes (status=0x%x)\n", status);
    }
    else if (WEXITSTATUS(status))
    {
      fprintf(stderr, "warning: child exited with error %d\n", WEXITSTATUS(status));
    }
    else
    {
      printf("info: child exited\n");
    }
  }
}

static void close_server_handles(struct server_state *state)
{
  int i;

  assert(state);

  /* close all open file descriptors */
  close(state->sockfd);
  for (i = 0; i < MAX_CHILDREN; i++)
  {
    if (state->children[i].worker_fd >= 0)
    {
      close(state->children[i].worker_fd);
    }
  }
}

static int handle_connection(struct server_state *state)
{
  struct sockaddr addr;
  socklen_t addrlen = sizeof(addr);
  int connfd;
  pid_t pid;
  int sockets[2];

  assert(state);

  /* accept incoming connection */
  connfd = accept(state->sockfd, &addr, &addrlen);
  if (connfd < 0)
  {
    if (errno == EINTR)
      return 0;
    perror("error: accepting new connection failed");
    return -1;
  }

  /* can we support more children? */
  if (state->child_count >= MAX_CHILDREN)
  {
    fprintf(stderr,
            "error: max children exceeded, dropping incoming connection\n");
    return 0;
  }

  /* prepare notification channel */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
  {
    perror("error: opening stream socket pair");
    return -1;
  }

  /* fork process to handle it */
  pid = fork();
  if (pid == 0)
  {
    /* worker process */
    close(sockets[0]);
    close_server_handles(state);
    worker_start(connfd, sockets[1], state->db);
    /* never reached */
    exit(1);
  }
  if (pid == -1)
  {
    perror("error: cannot fork");
    close(connfd);
    close(sockets[0]);
    close(sockets[1]);
    return -1;
  }

  /* register child */
  child_add(state, sockets[0]);

  /* close worker handles in server process */
  close(connfd);
  close(sockets[1]);

  return 0;
}

static int handle_s2w_closed(struct server_state *state, int index)
{
 // printf("server: handle_s2w_closed\n");
  assert(state->children[index].worker_fd >= 0);

  /* if the other end of worker_fd was closed, the worker exited */
  close(state->children[index].worker_fd);
  state->children[index].worker_fd = -1;
  state->child_count--;
  return 0;
}

static int handle_w2s_read(struct server_state *state, int index)
{
  char buf[256];
  int i;
  ssize_t r;

  /* one or more of the workers want us to notify everyone;
     * these notifications are idempotent so the number does not
     * actually matter, nor does the data sent over the pipe
     */
  errno = 0;
  r = read(state->children[index].worker_fd, buf, sizeof(buf));
  if (r < 0)
  {
    perror("error: read socketpair failed");
    return -1;
  }

  /* this means the worker closed its end of the socket pair */
  if (r == 0)
  {
    handle_s2w_closed(state, index);
    return 0;
  }

  /* notify each worker */
  for (i = 0; i < MAX_CHILDREN; i++)
  {
    state->children[i].pending = 1;
  }

  return 0;
}

static int handle_s2w_write(struct server_state *state, int index)
{
  char buf = 0;
  ssize_t r;

  assert(state->children[index].worker_fd >= 0);

  /* ready to send a pending notification; we just want to notify the worker,
     * the data sent does not actually matter
     */
  if (!state->children[index].pending)
    return 0;

  r = write(state->children[index].worker_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE)
  {
    perror("error: write socketpair failed");
    return -1;
  }
  state->children[index].pending = 0;
  return 0;
}

static void handle_sigchld(int signum)
{
  /* do nothing */
}

static void register_signals(void)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));

  /* SIGCHLD should interrupt accept */
  sa.sa_handler = handle_sigchld;
  sigaction(SIGCHLD, &sa, NULL);

  /* SIGPIPE should be ignored */
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);
}

static void usage(void)
{
  printf("usage:\n");
  printf("  server port\n");
  exit(1);
}

static int server_state_init(struct server_state *state, sqlite3 *db)
{
  int i;

  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));
  state->sockfd = -1;
  for (i = 0; i < MAX_CHILDREN; i++)
  {
    state->children[i].worker_fd = -1;
  }

  /* TODO any additional server state initialization */
  state->db = db;

  //initialize sql table
  int res_create = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS msg(id INTEGER PRIMARY KEY , timestamp integer NOT NULL, msg text NOT NULL, sender text NOT NULL, receiver text NOT NULL, msg_type integer NOT NULL)", NULL, NULL, NULL);
    if (res_create != 0)
    {
        fprintf(stderr, "Unable to create headers for database. Error: %s \n", sqlite3_errmsg(db));
    }
  res_create = sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS users(username TEXT NOT NULL UNIQUE, salt text NOT NULL, hash text NOT NULL, status integer, PRIMARY KEY (username))",NULL,NULL,NULL);



  if (res_create != 0)
  {
    fprintf(stderr, "Unable to create headers for database. Error: %s \n", sqlite3_errmsg(db));
  }
 // res_create = sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS msg(id INTEGER PRIMARY KEY, msg_type	text NOT NULL,msg_len INTEGER NOT NULL, sender TEXT NOT NULL  , receiver TEXT, timestamp INTEGER NOT NULL, msg BLOB NOT NULL, FOREIGN KEY (sender)  REFERENCES users(username))",NULL,NULL,NULL);
   // if (res_create != 0)
   // {
   //     fprintf(stderr, "Unable to create headers for database2. Error: %s \n", sqlite3_errmsg(db));
   // }
    sqlite3_busy_timeout( state->db, 2000 );
  return 0;
}

static void server_state_free(struct server_state *state)
{
  int i;

  for (i = 0; i < MAX_CHILDREN; i++)
  {
    close(state->children[i].worker_fd);
  }

  memset(state, 0, sizeof(*state));
}

static int handle_incoming(struct server_state *state)
{
  int fdmax, i, worker_fd, r, success = 1;
  fd_set readfds, writefds;

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  /* wake on for incoming connections */
  FD_SET(state->sockfd, &readfds);
  fdmax = state->sockfd;
  for (i = 0; i < MAX_CHILDREN; i++)
  {
    worker_fd = state->children[i].worker_fd;
    if (worker_fd < 0)
      continue;
    /* wake on worker-to-server notifications */
    FD_SET(worker_fd, &readfds);
    /* wake on when we can notify the worker */
    if (state->children[i].pending)
    {
      FD_SET(worker_fd, &writefds);
    }
    fdmax = max(fdmax, worker_fd);
  }

  /* wait for at least one to become ready */
  r = select(fdmax + 1, &readfds, &writefds, NULL, NULL);
  if (r < 0)
  {
    if (errno == EINTR)
      return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(state->sockfd, &readfds))
  {
    if (handle_connection(state) != 0)
      success = 0;
  }

  for (i = 0; i < MAX_CHILDREN; i++)
  {
    /* handle incoming notifications */
    worker_fd = state->children[i].worker_fd;
    if (worker_fd < 0)
      continue;

    if (FD_ISSET(worker_fd, &readfds))
    {
      if (handle_w2s_read(state, i) != 0)
        success = 0;
    }

    /* send outgoing notifications (note that handle_w2s_read
         * may have cleared the fd)
         */
    worker_fd = state->children[i].worker_fd;
    if (worker_fd < 0)
      continue;

    if (FD_ISSET(worker_fd, &writefds))
    {
      if (handle_s2w_write(state, i) != 0)
        success = 0;
    }
  }
  return success ? 0 : -1;
}

int main(int argc, char **argv)
{
  uint16_t port;
  struct server_state state;
  sqlite3 *db;

  /* check arguments */
  if (argc != 2)
    usage();
  if (parse_port(argv[1], &port) != 0)
    usage();

  /* database initalization */
  int result_open = sqlite3_open("chat.db", &db);
  if (result_open != 0)
  {
    fprintf(stderr, "Unable to open database. Error: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }

  /* preparations */
  server_state_init(&state, db);
  register_signals();

  /* start listening for connections */
  state.sockfd = create_server_socket(port);
  if (state.sockfd < 0)
    return 1;

  /* wait for connections */
  for (;;)
  {
    children_check(&state);
    if (handle_incoming(&state) != 0)
      break;
  }

  /* clean up */
  sqlite3_close(db);
  server_state_free(&state);
  close(state.sockfd);

  return 0;
}
