#include "../include/main.h"
#include "../include/sender.h"
#include "../include/receiver.h"
#include "../include/server_client.h"
#include "../include/encrypt_decrypt.h"

extern int errno;   // error number from <errno.h>
extern char *session_path;

char err_msg[ERR_MSG_LEN];  // buffer for error messages

// Helper functions

static void handle_errors(const char *msg, const char *format)
{
    snprintf(err_msg, ERR_MSG_LEN, "%s: %s\n", msg, format);
    fprintf(stddbg, err_msg);
}


static void thread_function_run_node(args_s *args) {
    run_node(args->name, args->ip, args->port, args->backlog);
}


static void print_options() {
    printf("\n\n");
    printf("Options:\n");
    printf("\t%d - Send a file\n", OPT_SEND);
    printf("\t%d - list connected nodes\n", OPT_LIST);
    printf("\t%d - disconnect from networks\n", OPT_DISC);
    printf("\t%d - help\n", OPT_HELP);
    printf("\n");

    printf("Enter option: ");
    
}


static void clear_screen() 
{
    fflush(stdout);
    system("clear");
}


static void clear_input() 
{
    while (getchar() != '\n' && getchar() != EOF);
}

// TUI

static void list_nodes() 
{
    size_t connected_amount;
    node_s *nodes = get_connected_nodes(OPT_LIST_AMOUNT, &connected_amount);
    if (!nodes) return; // no nodes connected or malloc failed
    
    size_t amount = OPT_LIST_AMOUNT == -1 ? connected_amount : OPT_LIST_AMOUNT;
    amount = OPT_LIST_AMOUNT > connected_amount ? connected_amount : amount;
    printf("%zu nodes listed out of %zu nodes connected\n", amount, connected_amount);
    for (size_t i = 0; i < amount; ++i) {
        printf("Node %ld:\n", i);
        printf("\tID:   %s\n", nodes[i].id);
        printf("\tName: %s\n", nodes[i].name);
        printf("\tIP:   %s\n", inet_ntoa(nodes[i].addr->sin_addr));
        printf("\tPort: %d\n", ntohs(nodes[i].addr->sin_port));
    }

    free(nodes);
}


int main(int argc, char *argv[])
{
    // argv[1] - name of the node, NULL for default
    // argv[2] - port of the node, NULL for default

    clear_screen();

    // starting the node
    char name[NODE_NAME_LEN];
    if (argc >= 2 && !argv[1]) {
        if (strlen(getenv("USER")) > NODE_NAME_LEN - 1) {  // -1 for '\0'
            handle_errors("main - name too long", strerror(errno));
            return -1;
        }
        strcpy(name, argv[1]);
    } else {
        if (strlen(argv[0]) > NODE_NAME_LEN - 1) {  // -1 for '\0'
            handle_errors("main - name too long", strerror(errno));
            return -1;
        }
        strcpy(name, getenv("USER"));
    }
    
    int node_port;
    if (argc >= 3 && !argv[2]) {
        node_port = atoi(argv[1]);
    } else {
        node_port = DEFAULT_PORT;
    }
    
    pthread_t thread_run_node;
    args_s args;
    args.name = (char *)malloc(NODE_NAME_LEN);
    args.ip = (char *)malloc(17);

    strcpy(args.name, name);
    strcpy(args.ip, "0.0.0.0");
    args.port = node_port;
    args.backlog = 10;


    if (pthread_create(&thread_run_node, NULL, (void *)thread_function_run_node, &args) != 0) {
        handle_errors("main - failed to create thread", strerror(errno));
        return -1;
    }
    // finished starting the node
    char input[2];
    while (1) {
        print_options();
        fgets(input, 2, stdin);
        clear_screen();
        switch(atoi(input)) {
            case OPT_ERR:
                printf("error - please enter a valid input");
                break;
            case OPT_SEND:
                printf("unimplemented");
                break;
            case OPT_LIST:
                list_nodes();
                break;
            case OPT_DISC:
                printf("unimplemented");
                break;
            case OPT_HELP:
                printf("unimplemented");
                break;
            default:
                printf("error - no %d option", atoi(input));
                break;
        }

        clear_input();
    }

    // freeing memory
    free(args.name);
    free(args.ip);
}
