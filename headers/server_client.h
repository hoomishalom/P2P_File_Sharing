#ifndef SERVER_H_INCLUDED // include gaurd
#define SERVER_H_INCLUDED

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>

#define SERVER_stddbg stderr   // standard debbug output
#define SERVER_ERR_MSG_LEN 1024  // max error message length

#define MAX_NODES 16    // max number of nodes
#define MAX_SOCKET_FD 1024 // max number of socket fds

#define MAX_PACKET_SIZE 1024    // max packet size

// Node structre

#define NODE_ID_LEN 16
#define NODE_NAME_LEN 32

struct node_s;
typedef struct
{
    char id[NODE_ID_LEN];
    char name[NODE_NAME_LEN];
    struct sockaddr_in *addr;
} node_s;

// Timeouts

#define RUN_NODE_TIMEOUT_SECONDS 0 // timeout for run_node [Seconds]
#define RUN_NODE_TIMEOUT_USECONDS 10000 // timeout for run_node [USeconds]

// Message Types

#define MSG_TYPE_LEN 2

#define MSG_TYPE_NETCONN 0              // new network connection - BROADCAST
#define MSG_TYPE_NETDISC 1              // net work disconnection - BROADCAST
#define MSG_TYPE_NETCONN_APPROVED 2     // new network connection approved
#define MSG_TYPE_NETCONN_DISAPPROVED 3  // new network connection disapproved
#define MSG_TYPE_HEABEAT_CHECK 4        // checks if a node is still alive
#define MSG_TYPE_HEABEAT_RESPONSE 5     // responds to a heartbeat check
#define MSG_TYPE_SENDREQ 6              // send file request
#define MSG_TYPE_SENDANS 7              // send answer to request

// Disapprove Reasons

#define DISAPPROVE_REASON_LEN 2

#define DISAPPROVE_REASON_FULL 0
#define DISAPPROVE_REASON_NAME_TOO_LONG 1
#define DISAPPROVE_REASON_NAME_TAKEN 2

// packet structre

#define PACKET_DELIMITER "|"
#define DATA_DELIMITER "#"


/*
NOTE: packet format is:
    <id>|<type>|<data1>#...#<dataN>
    where:
        <id> is the id of the node (if needed)
        <type> is the type of the message
        <data1>...<dataN> are the data fields (if needed)

    
    formats when creating a packet:
        MSG_TYPE_NETCONN - |MSG_TYPE_NETCONN|
        MSG_TYPE_NETDISC - |MSG_TYPE_NETDISC|
        MSG_TYPE_NETCONN_APPROVED - <node_id>|MSG_TYPE_NETCONN_APPROVED|
        MSG_TYPE_NETCONN_DISAPPROVED - |MSG_TYPE_NETCONN_DISAPPROVED|<disapprove_reason>#<node_ip>#<node_port>
        MSG_TYPE_HEABEAT_CHECK - 
        MSG_TYPE_HEABEAT_RESPONSE - 
        MSG_TYPE_SENDREQ - 
        MSG_TYPE_SENDANS -
    formats when packets get sent:
        MSG_TYPE_NETCONN - <id>|MSG_TYPE_NETCONN|<name>
        MSG_TYPE_NETDISC - <id>|MSG_TYPE_NETDISC|
        MSG_TYPE_NETCONN_APPROVED - <id>|MSG_TYPE_NETCONN_APPROVED|<name>
        MSG_TYPE_NETCONN_DISAPPROVED - |MSG_TYPE_NETCONN_DISAPPROVED|<reason>
        MSG_TYPE_HEABEAT_CHECK - 
        MSG_TYPE_HEABEAT_RESPONSE - 
        MSG_TYPE_SENDREQ - 
        MSG_TYPE_SENDANS - 
    
*/

// other defines
#define MAX_INT_LEN 11

// functions

/*
converts an integer to a string

@param num number to convert
@param output pointer to the output buffer
@return string representation of the number
*/
static char* itoa(int num, char *output);

/*
centerlized way of printing error messages
format: msg: info

@param msg message
@param info added info 
*/
static void handle_errors(const char *msg, const char *info);

/*
creates a formatted packet (message)

@param id id (if needed)
@param type type of the message (MSG_TYPE_...)
@param data data field, separeted by DATA_DELIMITER
@param packet pointer to the packet buffer
*/
static void make_packet(const char *id, const int type, const char *data, char *packet);

/*
generates a random id for nodes

@param output pointer to the output buffer
@param size size of id (minus 1 for null terminator)
*/
static void generate_id(char *output, size_t size);

/*
lookups node struct based on id (from the nodes array)

@param id id to look for
@return pointer to the node struct, NULL if not found
*/
static node_s* get_node_by_id(const char *id);

/*
checks if the name is availtable for use

@param name name to check
@return true if the name is available, false otherwise
*/
static bool is_name_available(const char *name);

/* 
checks if malloc returnd a null pointer, prints an error message according to the result
also makes the program stop

@param func_name name of the function that called malloc
@param ptr the return value of malloc
@return false if malloc failed, true otherwise
*/
static bool verify_malloc(const char *func_name, const void *ptr);

/*
frees allocated memory and closes sockets

@param sockets array of sockets
@param connected_sockets amount of opened sockets in the sockets array
@return exit code 0 on success, -1 otherwise
*/
static int cleanup(int sockets[], int connected_sockets);

/*
appends message to message queue

@param socket socket that will send the message
@param message message that will be sent
@return exit code 0 on success, -1 otherwise
*/
static int append_message(int socket, char *message);

/*
sets memebrs of a sockaddr_in struct

@param ip ip address
@param port port number
@param server_addr pointer to the sockaddr_in struct
@return exit code 0 on success, -1 otherwise
*/
static int set_socket_addr(const char *ip, const int port, struct sockaddr_in *server_addr);

/*
creates tcp socket, binds it to address and sets listening mode

@param server_addr address to bind the socket to
@param reuseaddr reuse address option (0 - off, 1 - on)
@param sock_backlog max number of connections backlog
@return socket socket file descriptor, -1 value on error
*/
static int create_listen_socket(struct sockaddr_in *server_addr, int reuseaddr, int sock_backlog);

/*
craetes the udp broadcasting socket and binds it to address

@param server_addr address to bind the socket to
@param reuseaddr reuse address option (0 - off, 1 - on)
@param broadcast broadcast option (0 - off, 1 - on)
@param backlog max number of connections backlog
@return socket socket file descriptor, -1 value on error
*/
static int create_broadcast_socket(struct sockaddr_in *server_addr, int reuseaddr, int broadcast, int backlog);

/*
connects this node to the network

@param broadcasting_socket socket to broadcast messages
@return exit code 0 on success, -1 otherwise
*/
int send_connect_to_network(int broadcasting_socket);

/*
approves a node trying to connect to the network

@param out_socket socket to send the message through
@param node_id id of the node
@return exit code 0 on success, -1 otherwise
*/
int send_approve_node_connection(int out_socket, const char *node_id);

/*
disapproves a node trying to connect to the network (for example: due to an unavailable name)

@param out_socket socket to send the message through
@param node_ip ip of the node
@param node_port port of the node
@param disapprove_reason reason for disapproval
@return exit code 0 on success, -1 otherwise
*/
int send_disapprove_node_connection(const int out_socket, const char *node_ip, int node_port, const int disapprove_reason);

/*
sends a broadcast message which indactes that the node is dissconecting from the network

@param socket broadcasting socket
@return exit code 0 on success, -1 otherwise
*/
int send_node_disconnect(int socket);

/*
interperets outcoming message and directs the message to the currect function

@param socket socket to send packet from
@param message message (the data memeber of a Message struct)
@return exit code 0 on success, -1 otherwise
*/
int message_interchange_out(int socket, char *message);

/*
handle a new node connectoin

@param socket socket that recieved the packet
@param node_id id of the node
@param node_name name of the node
@param node_addr address of the node
@return exit code 0 on success, -1 otherwise
*/
int recieve_node_connection(const int socket, const char *node_id, const char *node_name, const struct sockaddr_in *node_addr);

/*
interperets incoming Message and directs to currect function

@param socket socket which recieved the packet
@param message the data
@param addr address of the sender (if needed) NULL if not needed
@return exit code 0 on success, -1 otherwise
*/
int message_interchange_in(const int socket, char *message, const struct sockaddr_in *addr);

/*
starts the node, creates sockets and listens for incoming connections

@param name name of the node
@param ip ip of the node
@param port port of the node
@return exit code, 0 on success, -1 otherwise
*/
int run_node(const char *name, const char *ip, const int port, const int backlog);

/*
connects to network

@param socket socket that will be used to send connect message
@return exit code 0 on success, -1 otherwise
*/
int network_connect(int socket);

/*
disconnects from the network
*/
void network_disconnect();

#endif
