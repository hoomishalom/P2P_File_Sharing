#include "headers/server_client.h"
#include "headers/message_queue.h"

int main()
{
    run_node("testName", "0.0.0.0", 5005, 10);
}