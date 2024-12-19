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

#ifndef FILE_PATH_LEN
#define FILE_PATH_LEN 1024  // max length of the file path
#endif

/*
initliazes the program

@param dir_name name for session directory, NULL for default
@return exit code
*/
int init_encrypt_decrypt(char *dir_name);


#endif  // MAIN_HEADERS_H_INCLUDED