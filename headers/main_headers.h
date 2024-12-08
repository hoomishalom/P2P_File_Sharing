#ifndef MAIN_HEADERS_H_INCLUDED
#define MAIN_HEADERS_H_INCLUDED

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
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

#define RSA_KEY_BITS 2048  // RSA key bits

#endif  // MAIN_HEADERS_H_INCLUDED