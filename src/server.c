#include "../headers/main_headers.h"
#include "../headers/server.h"

#define errMsgLen 1024  // max error message length

#define stddbg stderr   // standard debbug output 

extern int errno;       // error number from <errno.h>

char errMsg[errMsgLen]; // buffer for error messages

static int setServerAddr(char *ip, int port, struct sockaddr_in *serverAddr) 
{
    // sets serverAddr
    serverAddr->sin_family = AF_INET; // sets protocol family
    serverAddr->sin_port = htons(port); // sets port
    if (inet_aton(ip, &serverAddr->sin_addr) == 0)    // sets serverAddr.sin_addr.s_addr
    {   
        snprintf(errMsg, sizeof(errMsg), "setServerAddr - Error setting serverAddr: %s\n", strerror(errno));
        fprintf(stddbg, errMsg);
        return -1;    // error return
    }
    return 0;
}

static int createServer(struct sockaddr_in serverAddr, int sockOption, int sockBacklog) 
{

    int serverSocket;

    // creates serverSocket
    if((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        snprintf(errMsg, errMsgLen, "createServer - Error creating server socket: %s\n", strerror(errno));
        fprintf(stddbg, errMsg);
        return -2;
    }

    // sets serverSocket options
    if((setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &sockOption, sizeof(sockOption))) == -1)
    {
        snprintf(errMsg, errMsgLen, "createServer - Error setting server socket options: %s\n", strerror(errno));
        fprintf(stddbg, errMsg);
        return -3;
    }

    // binds serverSocket to serverAddr
    if((bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) == -1)
    {
        snprintf(errMsg, errMsgLen, "createServer - Error binding server socket: %s\n", strerror(errno));
        fprintf(stddbg, errMsg);
        return -4;
    }

    // listens on serverSocket
    if((listen(serverSocket, sockBacklog)) == -1)
    {
        snprintf(errMsg, errMsgLen, "createServer - Error listening on server socket: %s\n", strerror(errno));
        fprintf(stddbg, errMsg);
        return -5;
    }

    return serverSocket;
}


