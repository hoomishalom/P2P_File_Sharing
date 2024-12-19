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

// Message Types

#define MSG_TYPE_LEN 2

#define MSG_TYPE_NETCONN 0   // new network connection
#define MSG_TYPE_NETCONN_APPROVED 1   // new network connection approved
#define MSG_TYPE_NETCONN_DISAPPROVED 2   // new network connection disapproved
#define MSG_TYPE_NETDISC 3   // net work disconnection
#define MSG_TYPE_SENDREQ 4   // send file request
#define MSG_TYPE_SENDANS 5   // send answer to request

// packet structre

#define PACKET_DELIMITER "||"
#define DATA_DELIMITER "##"

#endif

/*
NOTE: packet format is:
    <id>||<type>||<data1>##...##<dataN>
    where:
        <id> is the id of the node
        <type> is the type of the message
        <data1>...<dataN> are the data fields

    
    formats when creating a packet:
        MSG_TYPE_NETCONN - ||MSG_TYPE_NETCONN||
        MSG_TYPE_NETCONN_APPROVED - <node_id>||MSG_TYPE_NETCONN_APPROVED||
        MSG_TYPE_NETCONN_DISAPPROVED - ||MSG_TYPE_NETCONN_DISAPPROVED||<disapprove_reason>##<node_ip>##<node_port>
        MSG_TYPE_NETDISC -
        MSG_TYPE_SENDREQ -
        MSG_TYPE_SENDANS -
    formats when packets get sent:
        MSG_TYPE_NETCONN - <id>||MSG_TYPE_NETCONN||<name>
        MSG_TYPE_NETCONN_APPROVED - <id>||MSG_TYPE_NETCONN_APPROVED||<name>
        MSG_TYPE_NETCONN_DISAPPROVED - ||MSG_TYPE_NETCONN_DISAPPROVED||<reason>
        MSG_TYPE_NETDISC - 
        MSG_TYPE_SENDREQ - 
        MSG_TYPE_SENDANS - 
    
*/

/*
connects this node to the network

@param broadcasting_socket socket to broadcast messages
@return exit code -1 on error, 0 on success
*/
int send_connect_to_network(int broadcasting_socket);

/*
approves a node trying to connect to the network

@param out_socket socket to send the message through
@param node_id id of the node
@return exit code -1 on error, 0 on success
*/
int send_approve_node_connection(int out_socket, const char *node_id);

/*
disapproves a node trying to connect to the network (for example: due to an unavailable name)

@param out_socket socket to send the message through
@param node_ip ip of the node
@param node_port port of the node
@param disapprove_reason reason for disapproval
@return exit code -1 on error, 0 on success
*/
int send_disapprove_node_connection(const int out_socket, const char *node_ip, int node_port, const char *disapprove_reason);

/*
starts the node, creates sockets and listens for incoming connections

@param name name of the node
@param ip ip of the node
@param port port of the node
*/
int run_node(const char *name, const char *ip, const int port, const int backlog);
