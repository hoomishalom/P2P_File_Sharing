#include "../include/main.h"
#include "../include/sender.h"
#include "../include/receiver.h"
#include "../include/server_client.h"
#include "../include/encrypt_decrypt.h"

extern int errno;   // error number from <errno.h>

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


static void clear() {
    system("clear");
}

// Initialization

char tmp_template[FILE_PATH_LEN] = "/tmp/files_XXXXXX"; // template for mkdtemp function
char tmp_path[FILE_PATH_LEN];  // path of tmp function, output of mkdtemp function

mode_t session_mode = S_IRWXU | S_IROTH;    // modes for session folder
char *session_name = "/.session";    // name of the session dir
char session_path[FILE_PATH_LEN] = "";  // path of the session dir, output of mkdir function

int init_encrypt_decrypt(char *dir_name) {
    strcpy(tmp_path, tmp_template);

    if (!mkdtemp(tmp_path)) {
        handle_errors("init_encrypt_decrypt - creating temp dir failed", strerror(errno));
        return -1;
    }
    printf("%s\n", tmp_path);

    if (dir_name != NULL) { // user inputed dir_name
        session_name = dir_name;
    }

    // create session_path
    strcat(session_path, tmp_path);
    strcat(session_path, session_name);

    if (mkdir(session_path, session_mode) == -1) {  // try to make the session dir
        handle_errors("init_encrypt_decrypt - creating session dir failed", strerror(errno));
        return -1; 
    }
    return 0;
}


void print_options() {
    printf("\n\n");
    printf("Options:\n");
    printf("\t1 - Send a file\n");
    printf("\t2 - list connected nodes\n");
    printf("\t3 - disconnect from networks\n");
    printf("\t9 - help\n");
    printf("\n");

    printf("Enter option: ");
    
}

int main(int argc, char *argv[])
{
    // argv[1] - name of the node, NULL for default
    // argv[2] - port of the node, NULL for default

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
        switch(atoi(input)) {
            case OPT_ERR:
                clear();
                printf("error - please enter a valid input");
                break;
            case OPT_SEND:
                printf("unimplemented\n");
                break;
            case OPT_LIST:
                printf("unimplemented\n");
                break;
            case OPT_DISC:
                printf("unimplemented\n");
                break;
            case OPT_HELP:
                printf("unimplemented\n");
                break;

        }

    }

    // freeing memory
    free(args.name);
    free(args.ip);
}
