#include "../headers/main.h"
#include "../headers/sender.h"
#include "../headers/receiver.h"
#include "../headers/client.h"
#include "../headers/server.h"
#include "../headers/encrypt_decrypt.h"

extern int errno;   // error number from <errno.h>

char err_msg[ERR_MSG_LEN];  // buffer for error messages

// Helper functions

static void handle_errors(const char *msg, const char *format)
{
    snprintf(err_msg, ERR_MSG_LEN, "%s: %s\n", msg, format);
    fprintf(stddbg, err_msg);
}

// Initialization

char tmp_template[FILE_PATH_LEN] = "/tmp/files_XXXXXX"; // template for mkdtemp function
char tmp_path[FILE_PATH_LEN];  // path of tmp function, output of mkdtemp function

mode_t session_mode = S_IRWXU | S_IROTH;    // modes for session folder
char *session_name = "/.session";    // name of the session dir
char session_path[FILE_PATH_LEN] = "";  // path of the session dir, output of mkdir function

int init_encrypt_decrypt(char *dir_name) {
    strcpy(tmp_path, tmp_template);
    mkdtemp(tmp_path);

    if(tmp_path == NULL) 
    {
        handle_errors("init_encrypt_decrypt - creating temp dir failed", strerror(errno));
        return -1;
    }

    if(dir_name != NULL) // user inputed dir_name
    {
        session_name = dir_name;
    }

    // create session_path
    strcat(session_path, tmp_path);
    strcat(session_path, session_name);

    if(mkdir(session_path, session_mode) == -1) // try to make the session dir
    {
        handle_errors("init_encrypt_decrypt - creating session dir failed", strerror(errno));
        return -2; 
    }
}


