#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include<sys/stat.h>
#include "util.h"
#include <ctype.h>

int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  assert(hostname);
  assert(addr);

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host) {
    if (host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      assert(host->h_length == sizeof(*addr));
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  fprintf(stderr, "error: unknown host: %s\n", hostname);
  return -1;
}

int max(int x, int y) {
  return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p) {
  char *endptr;
  long value;

  assert(str);
  assert(port_p);

  /* convert string to number */
  errno = 0;
  value = strtol(str, &endptr, 0);
  if (!value && errno) return -1;
  if (*endptr) return -1;

  /* is it a valid port number */
  if (value < 0 || value > 65535) return -1;

  *port_p = value;
  return 0;
}

// waiting part is (modified) from this doc: https://www.ibm.com/docs/en/zos/2.2.0?topic=functions-exec
int exec(char *arg[]){
    pid_t pid;
    int status;
    if ((pid = fork()) < 0)
        perror("fork() error");
    else if (pid == 0) {
        //child pid

        int fd = open("/dev/null", O_WRONLY);
        if(fd < 0){
            printf("could not open dev/null");
            return -1;
        }
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);

        execv(arg[0], arg);
        printf("error in execv\n");
        exit(1);
    } else{
        //printf("parent has forked child with pid of %d\n", (int) pid);
        if((pid = wait(&status)) == -1){
            printf("wait() error\n");
            return -1;
        }
        else{
            if(WIFEXITED(status)){
                //printf("child exited with status of %d\n", WEXITSTATUS(status));
                return 0;
            }
            else if(WIFSIGNALED(status)){
                printf("child was terminated by signal %d\n",WTERMSIG(status));
                return -1;
            }
            else if(WIFSTOPPED(status)){
                printf("child was stopped by signal %d\n", WSTOPSIG(status));
                return -1;
            }
            else{
                printf("something went horribly wrong.\n");
                return -1;
            }

        }
    }
    return 0;
}


int check_length(char *text, int minLen, int maxLen){
    size_t len = strlen(text);
   return (len >= minLen && len <= maxLen );

}

void printHex(int size, unsigned char *buf){
    for(int j = 0; j < size; j++)
        printf("%02X",buf[j]);
    printf("\n");

}

void printPkey(EVP_PKEY *key){
    assert(key);
    printf("pkey:\n");
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(bp, key, 1, NULL);
    BIO_free(bp);
}



/**
 * @brief               Validates access to client's keys.
 * @param               usr sanitized username
 * @return              0 for correct password, 1 for wrong password, -1 on errors.
 */
int validate_clientkey_access(char *usr, char *pass){
    assert(usr);
    assert(pass);

    unsigned char *hash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
    if(hash_password(hash,pass) != 0){
        free(hash);
        return -1;
    }
    FILE *fp;
    char path[256];
    memset(path,0,256);
    snprintf(path,256,"clientkeys/%s/hash.bin",usr);
    fp = fopen(path,"rb");
    if(fp == NULL) {
        printf("file can't be opened\n");
        free(hash);
        return -1;
    }

    unsigned char *storedHash = calloc(SHA256_HASH_SIZE , sizeof(unsigned char));
    if(fread(storedHash,1,SHA256_HASH_SIZE,fp) <= 0){
        printf("could not read the hash file\n");
        free(hash);
        free(storedHash);
        fclose(fp);
        return -1;
    }
    if(memcmp(storedHash,hash,SHA256_HASH_SIZE) !=0){
        printf("wrong password! you can't access keys.\n");
        free(hash);
        free(storedHash);
        fclose(fp);
        return 1;
    }

    free(hash);
    free(storedHash);
    fclose(fp);
    return 0;
}

/**
 * @param               usr sanitized path
 */
int fileExists(const char *filename){
    struct stat buffer;
    return (stat(filename,&buffer) == 0);

}


LinkedList* init_list(void){
    LinkedList *list = malloc(sizeof(LinkedList)) ;
    list->head = NULL ;
    list->tail = NULL ;
    //test_list(list);
    return list ;
}
int is_empty(LinkedList *list) {
    return (list->head == NULL) && (list->tail == NULL);
}
void insert_node(LinkedList *list, void *data){
    QNode *newNode =  malloc(sizeof(struct QNode));
    newNode->data = data;
    newNode->next = NULL;
    // list is empty.new node is head and tail.
    if(is_empty(list)){
        newNode->prev = NULL;
        list->head = newNode;
        list->tail = newNode;
    } else {
        newNode->prev = list->tail;
        list->tail->next = newNode;
        list->tail = newNode;
    }
}
QNode* get_node(LinkedList *list, char *name){
    if(is_empty(list)) {
        return NULL;
    } else {
        QNode *temp = list->head;
        while(temp){
            struct api_msg *msg = temp->data;
            if((strncmp(name, msg->privateMsg.sender, MAX_USR_LENGTH) == 0) || (strncmp(name, msg->privateMsg.receiver, MAX_USR_LENGTH) == 0)) {
                return temp;
            }
            temp = temp->next;
        }
        return NULL;
    }
}

int remove_node(LinkedList *list, QNode *node){
    if(is_empty(list)) {
        return 1;
    } else {
        if(list->head == node)
            list->head = node->next;
        if(list->tail == node)
            list->tail = node->prev;
        if(node->next != NULL)
            node->next->prev = node->prev;
        if(node->prev != NULL)
            node->prev->next = node->next;
        free(node->data);
        free(node);
        return 0;
    }

}

void print_list(LinkedList *list){
    if(is_empty(list)) {
        return;
    } else {
        printf("print_list:\n");
        QNode *temp = list->head;
        while (temp){
            if(temp->data){
                struct api_msg *msg = temp->data;
                printf("private msg from: '%s' to '%s'\n", msg->privateMsg.sender,msg->privateMsg.receiver);
            }
            temp = temp->next;
        }
    }
}

void list_free(LinkedList *list){
    if(!list) return;
    QNode *curr = list->head;
    QNode *next = NULL;
    while(curr){
        next = curr->next;
        if(curr->data)
            free(curr->data);
        free(curr);
        curr = next;
    }
}
//todo:test list functionality and memory leaks. remove this later
void test_list(LinkedList *list){
    printf("test list\n");
    printf("list is empty: %d\n", is_empty(list));
    struct api_msg *msg = calloc(1, sizeof(struct api_msg));
    msg->type = CMD_PRIVATE_MSG;
    strncpy(msg->privateMsg.sender,"LTS1",MAX_USR_LENGTH);
    strncpy(msg->privateMsg.receiver,"LTR1",MAX_USR_LENGTH);
    insert_node(list,msg);
    struct api_msg *msg2 = calloc(1, sizeof(struct api_msg));
    msg2->type = CMD_PRIVATE_MSG;
    strncpy(msg2->privateMsg.sender,"LTS2",MAX_USR_LENGTH);
    strncpy(msg2->privateMsg.receiver,"LTR2",MAX_USR_LENGTH);
    insert_node(list,msg2);
    print_list(list);
    printf("getting node with user LTS2\n");
    QNode *temp = get_node(list,"LTS2");
    printf("node returned: %s\n",((struct api_msg*)temp->data)->privateMsg.sender);
    printf("removing LTS2\n");
    remove_node(list, temp);
    print_list(list);
    printf("removing LTS1\n");
    temp = get_node(list,"LTS1");
    remove_node(list, temp);
    printf("list is empty: %d\n", is_empty(list));
    print_list(list);
    struct api_msg *msg3 = calloc(1, sizeof(struct api_msg));
    msg3->type = CMD_PRIVATE_MSG;
    strncpy(msg3->privateMsg.sender,"LTS3",MAX_USR_LENGTH);
    strncpy(msg3->privateMsg.receiver,"LTR3",MAX_USR_LENGTH);
    struct api_msg *msg4 = calloc(1, sizeof(struct api_msg));
    msg4->type = CMD_PRIVATE_MSG;
    strncpy(msg4->privateMsg.sender,"LTS3",MAX_USR_LENGTH);
    strncpy(msg4->privateMsg.receiver,"LTR3",MAX_USR_LENGTH);
    struct api_msg *msg5 = calloc(1, sizeof(struct api_msg));
    msg5->type = CMD_PRIVATE_MSG;
    strncpy(msg5->privateMsg.sender,"LTS3",MAX_USR_LENGTH);
    strncpy(msg5->privateMsg.receiver,"LTR3",MAX_USR_LENGTH);
    insert_node(list,msg3);
    insert_node(list,msg4);
    insert_node(list,msg5);
    print_list(list);
    printf("removing all msgs from LTS3\nremoved %d messages.\n",remove_msgs_from_user(list,"LTS3"));
    print_list(list);
    printf("list is empty: %d\n", is_empty(list));
    printf("test done\n");

}

int remove_msgs_from_user(LinkedList *list, char *name){
    if(is_empty(list)) {
        return -1;
    } else {
        int r = 0;
        QNode *node = get_node(list,name);
        while (node){
            remove_node(list, node);
            r++;
            node = get_node(list,name);
        }
        return r;
    }
}


int dec_msgs_from_user(LinkedList *list, char *sender, char *receiver, char *password){
    if(is_empty(list)) {
        return 0;
    } else {
        int ret = 0;
        QNode *node = get_node(list,sender);
        while (node){
            struct api_msg *msg = node->data;
            unsigned char *out = calloc(1, MAX_MESSAGE_LENGTH);
            int r;
            if(strcmp(msg->privateMsg.sender,sender) == 0)
                r = aes_dec(msg->privateMsg.sender,password,msg->privateMsg.receiver,(unsigned char*)msg->privateMsg.message,out,&msg->privateMsg.len);
            else
                r = aes_dec(msg->privateMsg.receiver,password,msg->privateMsg.sender,(unsigned char*)msg->privateMsg.message,out,&msg->privateMsg.len);
            if(r == 0){
                printf("%s %s: @%s %s", msg->time, msg->privateMsg.sender,msg->privateMsg.receiver, out);
                free(out);
            } else{
                //printf("skipping msg\n");
                free(out);
                node = get_next_node(list,node,sender);
                continue;
            }
            remove_node(list, node);
            ret++;
            node = get_node(list,sender);
        }
        return ret;
    }
}
//returns 1 if valid, 0 otherwise
int valid_username(char *username, char *allowed){
    assert(username);
    assert(allowed);
    if(!check_length(username,MIN_USR_LENGTH,MAX_USR_LENGTH))
        return 0;

    //char *ret = strpbrk(username,notAllowed);
    if(!isalnum(username[0])){
        printf("error: username must start with a character or a number\n");
        return 0;
    }
    for(int i = 0; i < strlen(username); i++){
        if(!isalnum(username[i]) && !strchr(allowed,username[i])){
            printf("error: invalid character '%c' in username\n",username[i]);
            return 0;
        }
    }
    return 1;

}


int send_queued_msgs_to_user(LinkedList *list, char *sender, char *receiver, char *password, int fd, SSL *ssl, EVP_PKEY *evpKey){
    if(is_empty(list)) {
        return 0;
    } else {
        int ret = 0;
        QNode *node = get_node(list,receiver);
        while (node){
            struct api_msg *msg = node->data;
            unsigned char *outbuff = calloc(1, MAX_MESSAGE_LENGTH+1);
            int encLen;
            int r = aes_enc(msg->privateMsg.sender,password,msg->privateMsg.receiver,(unsigned char*)msg->privateMsg.message,outbuff,&encLen);
            if(r != 0) {
                free(outbuff);
                return -1;
            }
            memset(msg->privateMsg.message, 0, sizeof(msg->privateMsg.message));
            memcpy(msg->privateMsg.message, outbuff, sizeof(msg->privateMsg.message));
            msg->privateMsg.len = encLen;
            free(outbuff);
            sign(msg,evpKey);
            if(api_send(fd,msg,ssl) !=0) return -1;

            remove_node(list, node);
            ret++;
            node = get_node(list,receiver);
        }
        return ret;
    }
}


QNode* get_next_node(LinkedList *list,QNode *node, char *name){
    if(is_empty(list)) {
        return NULL;
    } else {
        QNode *temp = node->next;
        while(temp){
            struct api_msg *msg = temp->data;//should i cast here??
            if((strncmp(name, msg->privateMsg.sender, MAX_USR_LENGTH) == 0) || (strncmp(name, msg->privateMsg.receiver, MAX_USR_LENGTH) == 0)) {
                return temp;
            }
            temp = temp->next;
        }
        return NULL;
    }
}


int waiting_for_key(LinkedList *list, char *name){
    if(is_empty(list)) {
        return 0;
    } else {
        QNode *temp = list->head;
        while(temp){
            struct api_msg *msg = temp->data;
            if((strncmp(name, msg->privateMsg.receiver, MAX_USR_LENGTH) == 0)){
                return 1;
            }
            temp = temp->next;
        }
        return 0;
    }
}