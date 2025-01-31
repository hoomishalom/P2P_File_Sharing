#include "../headers/server_client.h"
#include "../headers/message_queue.h"

extern int errno;   // error number from <errno.h>

char err_msg[SERVER_ERR_MSG_LEN];   // buffer for error messages

int server_port;

node_s server_node;
node_s tcp_socket;  // TODO:
node_s broadcasting_socket; // TODO:
node_s udp_socket;  // TODO:

size_t connected_nodes = 0;
node_s *nodes[MAX_NODES];
MessageQueue *messages[MAX_NODES];

bool run = true;    // variable fot the program loop

bool busy = false;  // true if we in the proccess of sending a file
MessageQueue *return_messages;  /* if a node tries to send a file while we are busy, we will store it's adreess and send a message when we are done */

// Helper functions

static char* itoa(int num, char *output) {
    snprintf(output, MAX_INT_LEN, "%d", num);
}

static void handle_errors(const char *msg, const char *info)
{
    snprintf(err_msg, SERVER_ERR_MSG_LEN, "%s: %s\n", msg, info);
    fprintf(SERVER_stddbg, err_msg);
}


static void make_packet(const char *id, const int type, const char *data, char *packet)
{
    packet[0] = '\0';   // checks that packet is initialized
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


static bool is_name_available(const char *name)
{
    for (size_t i = 0; i < connected_nodes; i++) {
        if (strcmp(nodes[i]->name, name)) {
            return false;
        }
    }

    return true;
}


static bool verify_malloc(const char *func_name, const void *ptr) {
    char temp_buffer[SERVER_ERR_MSG_LEN];   // buffer to create error messagee
    snprintf(temp_buffer, sizeof(temp_buffer), "%s - failed to allocate memory", func_name);
    if (ptr == NULL) {
        handle_errors(temp_buffer, strerror(errno));
        return false;
    }
    return true;
}


static int cleanup(int sockets[], int connected_sockets)
{
    free(server_node.addr); // frees server_node addr
    server_node.addr = NULL;

    for (size_t i = 0; i < connected_nodes; i++) {
        if (nodes[i] != NULL && messages[i] != NULL) {
            free(nodes[i]->addr);   // frees node addr
            free(nodes[i]); // frees node
            del_queue(messages[i]); // frees message queue

            nodes[i] = NULL;
            messages[i] = NULL;
        }
    }

    for (size_t i = 0; i < connected_sockets; i++) {
        close(sockets[i]);  // closes socket
    }

    return 0;
}


static int append_message(int socket, char *message)
{
    if (messages[socket] == NULL) {
        handle_errors("append_message - bad socket", strerror(errno));
        return -1;
    }

    enqueue(messages[socket], message, strlen(message));
    return 0;
}


// Server functions
static int set_socket_addr(const char *ip, const int port, struct sockaddr_in *server_addr) 
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
        return -1;
    }

    // binds server_socket to server_addr
    if ((bind(socket_fd, (struct sockaddr*)server_addr, sizeof(*server_addr))) == -1)
    {
        handle_errors("create_server - Error binding server socket", strerror(errno));
        return -1;
    }

    // listens on server_socket
    if ((listen(socket_fd, sock_backlog)) == -1)
    {
        handle_errors("create_server - Error listening on server socket", strerror(errno));
        return -1;
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
        return -1;
    }

    // sets socket_fd options (SO_BROADCAST)
    if ((setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast))) == -1)
    {
        handle_errors("create_server - Error setting server socket option (SO_BROADCAST)", strerror(errno));
        return -1;
    }

    // binds socket_fd to server_addr
    if ((bind(socket_fd, (struct sockaddr*)server_addr, sizeof(*server_addr)) == -1))
    {
        handle_errors("create_server - Error binding server socket", strerror(errno));
        return -1;
    }
    return socket_fd;
}


// begin outbound networking functions
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
        handle_errors("send_connect_to_network - Error sending broadcast packet", strerror(errno));
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
        handle_errors("send_approve_node_connection - Error sending broadcast message", strerror(errno));
        return -1;
    }
    return 0;
}


int send_disapprove_node_connection(const int out_socket, const char *node_ip, int node_port, const int disapprove_reason)
{
    struct sockaddr_in node_addr;
    set_socket_addr(node_ip, node_port, &node_addr);

    char disapprove_reason_str[DISAPPROVE_REASON_LEN];
    itoa(disapprove_reason, disapprove_reason_str);

    char packet[MAX_PACKET_SIZE];

    make_packet("", MSG_TYPE_NETCONN_DISAPPROVED, disapprove_reason_str, packet);

    ssize_t sent_bytes = sendto(out_socket, packet, strlen(packet), 0, (struct sockaddr*)&node_addr, sizeof(node_addr));
    if (sent_bytes == -1)
    {
        handle_errors("send_disapprove_node_connection - Error sending broadcast message", strerror(errno));
        return -1;
    }
    return 0;
}


int send_node_disconnect(int socket)
{
    struct sockaddr_in broadcast_addr;
    set_socket_addr("255.255.255.255", server_port, &broadcast_addr);

    char packet[MAX_PACKET_SIZE];
    make_packet(server_node.id, MSG_TYPE_NETDISC, "", packet);

    int sent_bytes = sendto(socket, packet, strlen(packet), 0, (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    if (sent_bytes == -1) {
        handle_errors("send_node_disconnect - failed sending message", strerror(errno));
        return -1;
    }
    return 0;
}


int message_interchange_out(int socket, char *message)
{

    char *id = strtok(message, PACKET_DELIMITER);
    int type = atoi(strtok(NULL, PACKET_DELIMITER));
    char *data = strtok(NULL, PACKET_DELIMITER);

    switch(type) {
        case MSG_TYPE_NETCONN:
            if (send_connect_to_network(socket) != 0) {
                return -1;
            }
            break;
        case MSG_TYPE_NETDISC:
            if (send_node_disconnect(socket) != 0) {
                return -1;
            }
            break;
        case MSG_TYPE_NETCONN_APPROVED:
            if (send_approve_node_connection(socket, id) != 0) {
                return -1;
            }
            break;
        case MSG_TYPE_NETCONN_DISAPPROVED:
            char *node_ip = strtok(data, DATA_DELIMITER);
            int node_port = atoi(strtok(NULL, DATA_DELIMITER));
            int disapprove_reason = atoi(strtok(NULL, DATA_DELIMITER));
            if (send_disapprove_node_connection(socket, node_ip, node_port, disapprove_reason) != 0) {
                return -1;
            }
            break;
        case MSG_TYPE_SENDREQ:
            break;
        case MSG_TYPE_SENDANS:
            break;
        default:
            handle_errors("message_interchange_out - bad type", strerror(errno));
            return -1;
    }
    return 0;
}
// end outbound networking functions

// begin inbound networking functions
int recieve_node_connection(const int socket, const char *node_id, const char *node_name, const struct sockaddr_in *node_addr)
{
    if (connected_nodes >= MAX_NODES) {
        send_disapprove_node_connection(socket, inet_ntoa(node_addr->sin_addr), ntohs(node_addr->sin_port), DISAPPROVE_REASON_FULL);
        handle_errors("recieve_node_connection - too many nodes", strerror(errno));
        return -1;
    }


    if (strlen(node_name) > NODE_NAME_LEN) {
        send_disapprove_node_connection(socket, inet_ntoa(node_addr->sin_addr), ntohs(node_addr->sin_port), DISAPPROVE_REASON_NAME_TOO_LONG);
        handle_errors("recieve_node_connection - name too long", strerror(errno));
        return -1;
    }

    if (!is_name_available(node_name)) {
        send_disapprove_node_connection(socket, inet_ntoa(node_addr->sin_addr), ntohs(node_addr->sin_port), DISAPPROVE_REASON_NAME_TAKEN);
        handle_errors("recieve_node_connection - name not available", strerror(errno));
        return -1;
    }

    node_s *node = (node_s*)malloc(sizeof(node_s));
    if (!verify_malloc("recieve_node_connection", node)) {
        network_disconnect();   // something bad happened if malloc failed, thus we quit
        return -1;
    }

    strcpy(node->id, node_id);
    strcpy(node->name, node_name);
    node->addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    if (!verify_malloc("recieve_node_connection", node->addr)) {
        network_disconnect();   // something bad happened if malloc failed, thus we quit
        return -1;
    }
    memcpy(node->addr, node_addr, sizeof(struct sockaddr_in));

    nodes[connected_nodes] = node;
    messages[connected_nodes] = (MessageQueue*)malloc(sizeof(MessageQueue));
    if (!verify_malloc("recieve_node_connection", messages[connected_nodes])) {
        network_disconnect();   // something bad happened if malloc failed, thus we quit
        return -1;
    }
    queue_init(&(messages[connected_nodes]));
    verify_malloc("recieve_node_connection", messages[connected_nodes]);

    connected_nodes++;

    send_approve_node_connection(socket, node_id);

    return 0;
}


int message_interchange_in(const int socket, char *message, const struct sockaddr_in *addr)
{
    char *id = strtok(message, PACKET_DELIMITER);
    int type = atoi(strtok(NULL, PACKET_DELIMITER));
    char *data = strtok(NULL, PACKET_DELIMITER);

    int return_code = 0;

    switch(type) {
        case MSG_TYPE_NETCONN:
            char *name = strtok(data, DATA_DELIMITER);
            if (recieve_node_connection(socket, id, name, addr) != 0) {
                return -1;
            }
            break;
        case MSG_TYPE_NETDISC:
            break;
        case MSG_TYPE_NETCONN_APPROVED:
            break;
        case MSG_TYPE_NETCONN_DISAPPROVED:
            break;
        case MSG_TYPE_SENDREQ:
            break;
        case MSG_TYPE_SENDANS:
            break;
        default:
            handle_errors("message_interchange_in - bad type", strerror(errno));
            return -1;
    }

    return 0;
}
// end inbound networking functions

// begin outbound user interface functions
int network_connect(int socket)
{
    char connect_message[MAX_PACKET_SIZE];
    make_packet(" ", MSG_TYPE_NETCONN, " ", connect_message);

    if (append_message(socket, connect_message) == -1) {
        return -1;
    }

    return 0;
}

void network_disconnect()
{
    run = false;
}

// end outboud user interface functions

int run_node(const char *name, const char *ip, const int port, const int backlog)
{   
    server_port = port;
    // setup server address and sockets
    struct sockaddr_in server_addr;
    if (set_socket_addr(ip, server_port, &server_addr) < 0) {
        handle_errors("run_node - Error setting node address", strerror(errno));
        return -1;
    }

    int listen_socket = create_listen_socket(&server_addr, 1, backlog);
    if (listen_socket < 0) {
        handle_errors("run_node - Error creating listen_socket", strerror(errno));
        return -1;
    }

    int broadcast_socket = create_broadcast_socket(&server_addr, 1, 1, backlog);
    if (broadcast_socket < 0) {
        handle_errors("run_node - Error creating broadcast socket", strerror(errno));
        return -1;
    }

    // array of connected sockets
    int sockets[FD_SETSIZE];    // FD_SETSIZE is the largest aomunt of sockets the node can handle
    int connected_sockets = 0;

    sockets[connected_sockets] = listen_socket;
    connected_sockets++;

    sockets[connected_sockets] = broadcast_socket;
    connected_sockets++;

    // inits messages queues for init sockets
    queue_init(&(messages[listen_socket]));
    queue_init(&(messages[broadcast_socket]));

    verify_malloc("run_node", messages[listen_socket]);
    verify_malloc("run_node", messages[broadcast_socket]);

    // setup fd_sets
    fd_set read_sockets;
    fd_set write_sockets;

    FD_ZERO(&read_sockets);
    FD_ZERO(&write_sockets);

    FD_SET(listen_socket, &read_sockets);
    FD_SET(broadcast_socket, &read_sockets);

    FD_SET(listen_socket, &write_sockets);
    FD_SET(broadcast_socket, &write_sockets);

    int max_fd = listen_socket > broadcast_socket ? listen_socket : broadcast_socket;   // max_fd for select

    // setup server node
    generate_id(server_node.id, NODE_ID_LEN);
    strcpy(server_node.name, name);
    server_node.addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in)); // allocates memory for struct
    if (!verify_malloc("recieve_node_connection", server_node.addr)) {
        network_disconnect();   // something bad happened if malloc failed, thus we quit
        return -1;
    }

    set_socket_addr(ip, server_port, server_node.addr);

    struct timeval timeout;

    // appends MSG_TYPE_NETCONN packet to broadcast socket messages
    if (network_connect(broadcast_socket) == -1) { 
        handle_errors("run_node - failed connection", strerror(errno));
        return -1;
    }

    while (run) {
        fd_set ready_read_sockets = read_sockets;
        fd_set ready_write_sockets = write_sockets;
        
        timeout.tv_sec = RUN_NODE_TIMEOUT_SECONDS;
        timeout.tv_usec = RUN_NODE_TIMEOUT_USECONDS;  

        int activity;
        activity = select(max_fd + 1, &ready_read_sockets, &ready_write_sockets, NULL, &timeout);
        if (activity == -1) {
            handle_errors("run_node - Error in select", strerror(errno));
            return -1;
        }


        if (activity > 0){
            for (int i = 3; i < max_fd + 1; i++) { // i = 3 because 0, 1, 2 are reserved to stdin, stdout, stderr resepctively
                if(FD_ISSET(i, &ready_read_sockets)) {
                    if (i == broadcast_socket) {
                        struct sockaddr_in recieved_addr;
                        char recieved_packet[MAX_PACKET_SIZE];
                        int recieved_bytes = recvfrom(i, recieved_packet, MAX_PACKET_SIZE, 0, (struct sockaddr*)&recieved_addr, (socklen_t *)sizeof(recieved_addr));

                        if (recieved_bytes == -1) {
                            handle_errors("run_node - recieved bad packet", strerror(errno));
                        } else {
                            recieved_packet[recieved_bytes] = '\0'; // add null terminator to string
                            message_interchange_in(i, recieved_packet, &recieved_addr);
                        }
                    }
                    else if (i == listen_socket) {
                    }
                }

                if (FD_ISSET(i, &ready_write_sockets)) {
                    if (!is_empty(messages[i])) {
                        char data[QUEUE_MAX_DATA_SIZE];
                        for (int j = 0; j < messages[i]->len; j++) {
                            size_t msg_len = dequeue(messages[i], data);
                            message_interchange_out(i, data);
                        }
                    }
                }
            }
        }
    }

    char message[MAX_PACKET_SIZE];
    make_packet("", MSG_TYPE_NETDISC, "", message);
    message_interchange_out(broadcast_socket, message);

    cleanup(sockets, connected_sockets);
    return 0;
}
