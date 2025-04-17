#ifndef SERVER_H_INCLUDED   /* include gaurd */
#define SERVER_H_INCLUDED

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
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
#define NODE_NAME_LEN 128

struct node_s;
typedef struct{
    char id[NODE_ID_LEN];
    char name[NODE_NAME_LEN];
    struct sockaddr_in *addr;
} node_s;

// Timeouts

#define RUN_NODE_TIMEOUT_SECONDS 1 // timeout for run_node [Seconds]
#define RUN_NODE_TIMEOUT_USECONDS 0 // timeout for run_node [USeconds]

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
#define DISAPPROVE_REASON_OTHER 3

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

@param socket socket that received the packet
@param node_id id of the node
@param node_name name of the node
@param node_addr address of the node
@return exit code 0 on success, -1 otherwise
*/
int handle_received_node_connection(const int socket, const char *node_id, const char *node_name, const struct sockaddr_in *node_addr);

/*
handle a node dissconnection

@param id the id of the node
@param addr the address of the node
@return -1 on fail, 0 on success
*/
int handle_received_node_disconnect(const char *id, const struct sockaddr_in *addr);

/*
handle received approved connection

@param id id of the node
@param name name of the node
@param addr address of the node
@return exit code 0 on success, -1 otherwise
*/
int handle_received_approved_connection(const char *id, const char *name, const struct sockaddr_in *addr);

/*
interperets incoming Message and directs to currect function

@param socket socket which received the packet
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


// API

/*
gets a list of connected nodes
@param amount amount of nodes (or less if aren't enough), -1 for all
@param connected_amount output pointer to the amount of connected nodes
@return an array of nodes, needs to be freed
*/
node_s *get_connected_nodes(size_t amount, size_t *connected_amount);

#endif
