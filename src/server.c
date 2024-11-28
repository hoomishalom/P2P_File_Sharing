#include "../headers/main_headers.h"
#include "../headers/server.h"

extern int errno;       // error number from <errno.h>

char err_msg[ERR_MSG_LEN]; // buffer for error messages

static int setServerAddr(char *ip, int port, struct sockaddr_in *serverAddr) 
{
    // sets serverAddr
    serverAddr->sin_family = AF_INET; // sets protocol family
    serverAddr->sin_port = htons(port); // sets port
    if (inet_aton(ip, &serverAddr->sin_addr) == 0)    // sets serverAddr.sin_addr.s_addr
    {   
        snprintf(err_msg, sizeof(err_msg), "setServerAddr - Error setting serverAddr: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -1;    // error return
    }
    return 0;
}

static int createServer(struct sockaddr_in serverAddr, int sockOption, int sockBacklog) 
{

    int serverSocket;

    // creates serverSocket
    if((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        snprintf(err_msg, ERR_MSG_LEN, "createServer - Error creating server socket: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -2;
    }

    // sets serverSocket options
    if((setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &sockOption, sizeof(sockOption))) == -1)
    {
        snprintf(err_msg, ERR_MSG_LEN, "createServer - Error setting server socket options: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -3;
    }

    // binds serverSocket to serverAddr
    if((bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) == -1)
    {
        snprintf(err_msg, ERR_MSG_LEN, "createServer - Error binding server socket: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -4;
    }

    // listens on serverSocket
    if((listen(serverSocket, sockBacklog)) == -1)
    {
        snprintf(err_msg, ERR_MSG_LEN, "createServer - Error listening on server socket: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -5;
    }

    return serverSocket;
}


