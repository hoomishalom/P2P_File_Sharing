#ifndef MAIN_HEADERS_H_INCLUDED
#define MAIN_HEADERS_H_INCLUDED

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#ifndef stddbg
#define stddbg stderr   // standard debbug output
#endif  // stddbg

#ifndef ERR_MSG_LEN
#define ERR_MSG_LEN 1024  // max error message length
#endif  // ERR_MSG_LEN

#define DEFAULT_PORT 5005

typedef struct {
    char *name;
    char *ip;
    int port;
    int backlog;
} args_s;

// input options
#define OPT_ERR  0  // atoi returns 0 on error
#define OPT_SEND 1
#define OPT_LIST 2
#define OPT_DISC 3
#define OPT_HELP 9

#define OPT_LIST_AMOUNT -1  // amount of nodes that will be listed, -1 for all

#endif  // MAIN_HEADERS_H_INCLUDED