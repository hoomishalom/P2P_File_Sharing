#include "headers/message_queue.h"

int main() {
    MessageQueue queue;
    queue_init(&queue);
    enqueue(&queue, "Hello", 5);
    char data[MAX_DATA_SIZE];
    dequeue(&queue, data);
    printf(data);
    return 0;
}