#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <openssl/evp.h>
#include "crypto.h"
int lookup_host_ipv4(const char *hostname, struct in_addr *addr);
int max(int x, int y);
int parse_port(const char *str, uint16_t *port_p);
int check_length(char *text, int minLen, int maxLen);
void printHex(int size,unsigned char *buf);
int validatePath(char *path);
void printPkey(EVP_PKEY *key);
int validate_clientkey_access(char *usr, char *pass);
int fileExists(const char *filename);
typedef struct QNode{
    void *data;
    struct QNode *next;
    struct QNode *prev;
}QNode;
typedef struct LinkedList{
    struct QNode *head;
    struct QNode *tail;
}LinkedList;

LinkedList* init_list(void);
int is_empty(LinkedList *list);
void insert_node(LinkedList *list, void *data);
QNode* get_node(LinkedList *list, char *name);
int remove_node(LinkedList *list, QNode *node);
void print_list(LinkedList *list);
void list_free(LinkedList *list);
void test_list(LinkedList *list);
int remove_msgs_from_user(LinkedList *list, char *name);
int dec_msgs_from_user(LinkedList *list, char *sender, char *receiver, char *password);
#endif /* defined(_UTIL_H_) */
