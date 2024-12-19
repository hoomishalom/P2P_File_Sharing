#include "../headers/server_client.h"
#include "../headers/message_queue.h"

extern int errno;   // error number from <errno.h>

char err_msg[SERVER_ERR_MSG_LEN];   // buffer for error messages

typedef struct
{
    char id[NODE_ID_LEN];
    char name[NODE_NAME_LEN];
    struct sockaddr_in *addr;
} node_s;

node_s server_node;

size_t connected_nodes = 0;
node_s *nodes[MAX_NODES];
MessageQueue *messages[MAX_NODES];

bool busy = false;  // true if we in the proccess of sending a file
MessageQueue *return_messages;  /* if a node tries to send a file while we are busy, we will store it's adreess and send a message when we are done */

// Helper functions

static void handle_errors(const char *msg, const char *format)
{
    snprintf(err_msg, SERVER_ERR_MSG_LEN, "%s: %s\n", msg, format);
    fprintf(SERVER_stddbg, err_msg);
}


static void make_packet(const char *id, const int type, const char *data, char *packet)
{
    strcat(packet, id);
    strcat(packet, PACKET_DELIMITER);

    char type_str[MSG_TYPE_LEN];
    snprintf(type_str, MSG_TYPE_LEN, "%d", type);
    strcat(packet, type_str);

    strcat(packet, PACKET_DELIMITER);
    strcat(packet, data);
}


static void generate_id(char *output, size_t size)
{
    char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    srand((unsigned int)time(0));
    for (size_t i = 0; i < size - 1; i++)   // -1 to leave space for null terminator
    {
        output[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    output[size - 1] = '\0'; // null terminator
}


static node_s* get_node_by_id(const char *id)
{
    for (size_t i = 0; i < connected_nodes; i++)
    {
        if (strcmp(nodes[i]->id, id) == 0)
        {
            return nodes[i];
        }
    }
    return NULL;    // node does not exist
}


static int cleanip()
{
    free(server_node.addr); // frees server_node addr
    for (size_t i = 0; i < connected_nodes; i++)
    {
        free(nodes[i]->addr);   // frees node addr
        free(nodes[i]); // frees node
        del_queue(messages[i]); // frees message queue
    }
}


// Server functions
static int set_socket_addr(const char *ip,const int port, struct sockaddr_in *server_addr) 
{
    // sets server_addr
    server_addr->sin_family = AF_INET; // sets protocol family
    server_addr->sin_port = htons(port); // sets port
    if (inet_aton(ip, &server_addr->sin_addr) == 0)    // sets server_addr.sin_addr.s_addr
    {   
        handle_errors("set_socket_addr - Error setting server_addr", strerror(errno));
        return -1;    // error return
    }
    return 0;
}


static int create_listen_socket(struct sockaddr_in *server_addr, int reuseaddr, int sock_backlog) 
{
    int socket_fd;

    // creates socket_fd
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        handle_errors("create_server - Error creating server socket", strerror(errno));
        return -1;
    }

    // sets server_socket options
    if ((setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr))) == -1)
    {
        handle_errors("create_server - Error setting server socket option (SO_REUSEADDR)", strerror(errno));
        return -2;
    }

    // binds server_socket to server_addr
    if ((bind(socket_fd, (struct sockaddr*)server_addr, sizeof(*server_addr))) == -1)
    {
        handle_errors("create_server - Error binding server socket", strerror(errno));
        return -3;
    }

    // listens on server_socket
    if ((listen(socket_fd, sock_backlog)) == -1)
    {
        handle_errors("create_server - Error listening on server socket", strerror(errno));
        return -4;
    }

    return socket_fd;
}


static int create_broadcast_socket(struct sockaddr_in *server_addr, int reuseaddr, int broadcast, int backlog)
{
    int socket_fd;

    // creates socket_fd
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1)
    {
        handle_errors("create_broadcast_socket - Error creating broadcast socket", strerror(errno));
        return -1;
    }

    // sets socket_fd options (SO_REUSEADDR)
    if ((setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr))) == -1)
    {
        handle_errors("create_server - Error setting server socket option (SO_REUSEADDR)", strerror(errno));
        return -2;
    }

    // sets socket_fd options (SO_BROADCAST)
    if ((setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast))) == -1)
    {
        handle_errors("create_server - Error setting server socket option (SO_BROADCAST)", strerror(errno));
        return -3;
    }

    // binds socket_fd to server_addr
    if ((bind(socket_fd, (struct sockaddr*)server_addr, sizeof(*server_addr)) == -1))
    {
        handle_errors("create_server - Error binding server socket", strerror(errno));
        return -4;
    }

    
    return socket_fd;
}


int send_connect_to_network(int broadcasting_socket)
{
    int port = ntohs(server_node.addr->sin_port);
    char *id = server_node.id;
    char *name = server_node.name;

    struct sockaddr_in broadcast_addr;
    set_socket_addr("255.255.255.255", port, &broadcast_addr);

    char packet[MAX_PACKET_SIZE];
    make_packet(id, MSG_TYPE_NETCONN, name, packet);

    ssize_t sent_bytes = sendto(broadcasting_socket, packet, strlen(packet), 0, (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    if(sent_bytes == -1)
    {
        handle_errors("broadcast_out - Error sending broadcast packet", strerror(errno));
        return -1;
    }
    return 0;
}


int send_approve_node_connection(const int out_socket, const char *node_id)
{
    char *id = server_node.id;
    char *name = server_node.name;

    node_s *node = get_node_by_id(node_id);

    char packet[MAX_PACKET_SIZE];
    make_packet(id, MSG_TYPE_NETCONN_APPROVED, name, packet);

    ssize_t sent_bytes = sendto(out_socket, packet, strlen(packet), 0, (struct sockaddr*)node->addr, sizeof(*(node->addr)));
    if (sent_bytes == -1)
    {
        handle_errors("broadcast_out_approve - Error sending broadcast message", strerror(errno));
        return -1;
    }
    return 0;
}


int send_disapprove_node_connection(const int out_socket, const char *node_ip, int node_port, const char *disapprove_reason)
{
    struct sockaddr_in node_addr;
    set_socket_addr(node_ip, node_port, &node_addr);

    char packet[MAX_PACKET_SIZE];
    make_packet("", MSG_TYPE_NETCONN_DISAPPROVED, disapprove_reason, packet);

    ssize_t sent_bytes = sendto(out_socket, packet, strlen(packet), 0, (struct sockaddr*)&node_addr, sizeof(node_addr));
    if (sent_bytes == -1)
    {
        handle_errors("broadcast_out_disapprove - Error sending broadcast message", strerror(errno));
        return -1;
    }
    return 0;
}


int send_node_disconnect(int socket)
{
    // TODO:
    // del_queue(messages[socket]);

}


static int message_interchange_out(int socket, char *message, size_t len, int port)
{
    char *id = strtok(message, PACKET_DELIMITER);
    int type = atoi(strtok(NULL, PACKET_DELIMITER));
    char *data = strtok(NULL, PACKET_DELIMITER);

    switch(type)
    {
        case MSG_TYPE_NETCONN:
            send_connect_to_network(socket);
            break;
        case MSG_TYPE_NETCONN_APPROVED:
            send_approve_node_connection(socket, id);
            break;
        case MSG_TYPE_NETCONN_DISAPPROVED:
            char *node_ip = strtok(data, DATA_DELIMITER);
            int node_port = atoi(strtok(NULL, DATA_DELIMITER));
            char *disapprove_reason = strtok(NULL, DATA_DELIMITER);
            send_disapprove_node_connection(socket, node_ip, node_port, disapprove_reason);
            break;
        case MSG_TYPE_NETDISC:
            send_node_disconnect(socket);
            break;
        case MSG_TYPE_SENDREQ:
            break;
        case MSG_TYPE_SENDANS:
            break;
    }
}


int run_node(const char *name, const char *ip, const int port, const int backlog)
{
    // setup server address and sockets
    struct sockaddr_in server_addr;
    if (set_socket_addr(ip, port, &server_addr) < 0)
    {
        handle_errors("run_node - Error setting node address", strerror(errno));
        return -1;
    }

    int listen_socket = create_listen_socket(&server_addr, 1, backlog);
    if (listen_socket < 0)
    {
        handle_errors("run_node - Error creating listen_socket", strerror(errno));
        return -2;
    }

    int broadcast_socket = create_broadcast_socket(&server_addr, 1, 1, backlog);
    if (broadcast_socket < 0)
    {
        handle_errors("run server - Error creating broadcast socket", strerror(errno));
        return -3;
    }

    // setup fd_sets
    fd_set read_sockets;
    fd_set write_sockets;

    FD_ZERO(&read_sockets);
    FD_ZERO(&write_sockets);

    FD_SET(listen_socket, &read_sockets);
    FD_SET(broadcast_socket, &read_sockets);

    int max_fd = listen_socket > broadcast_socket ? listen_socket : broadcast_socket;   // max_fd for select

    // setup server node
    generate_id(server_node.id, NODE_ID_LEN);
    strcpy(server_node.name, name);
    server_node.addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in)); // allocates memory for struct
    set_socket_addr(ip, port, server_node.addr);

    send_connect_to_network(broadcast_socket);      

    while (1)
    {
        fd_set ready_read_sockets = read_sockets;
        fd_set ready_write_sockets = write_sockets;

        int ready_amount;
        ready_amount = select(max_fd + 1, &ready_read_sockets, &ready_write_sockets, NULL, NULL);

        if (ready_amount == -1)
        {
            handle_errors("run_node - Error in select", strerror(errno));
            return -4;
        }

        for (int i = 3; i < max_fd + 1; i++) // i = 3 because 0, 1, 2 are reserved to stdin, stdout, stderr resepctively
        {
            if(FD_ISSET(i, &ready_read_sockets))
            {
                if (i == listen_socket) // New Transfer Request
                {
                    /* TODO: implement new connection*/
                }

                if (i == broadcast_socket) // New Node Connecting To Network
                {
                    /* TODO: implement adding nodes to the network*/
                }
            }

            if (FD_ISSET(i, &ready_write_sockets))
            {
                if (messages[i] != NULL)
                {
                    char data[QUEUE_MAX_DATA_SIZE];
                    for (int j = 0; j < messages[i]->len; j++)
                    {
                        size_t msg_len = dequeue(messages[i], data);
                        message_interchange_out(i, data, msg_len, port);
                    }
                }
            }
        }
    }
}
