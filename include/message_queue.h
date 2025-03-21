#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>

    #define QUEUE_MAX_DATA_SIZE 1024

    typedef struct Message Message;

    typedef struct MessageQueue MessageQueue;

    struct Message{
        char data[QUEUE_MAX_DATA_SIZE];
        size_t len;
        Message *next;
    };

    struct MessageQueue{
        Message *head;
        Message *tail;
        size_t len;
    };


    /*
    initializes a queue struct (does not check if malloc worked)

    @param queue pointer to pointer to the queue struct
    */
    void queue_init(MessageQueue **queue);

    /*
    checks if a queue is empty

    @param queue pointer to the queue struct
    @return 1 if the queue is empty, 0 otherwise
    */
    int is_empty(MessageQueue *queue);

    /*
    deletes a queue and frees all the memory

    @param queue pointer to the queue struct
    */
    void del_queue(MessageQueue *queue);

    /*
    creates a Message struct and adds it to the queue

    @param queue pointer to the queue struct
    @param data data to be added to the queue
    @return length of the data
    */
    void enqueue(MessageQueue *queue, const char *data, size_t len);

    /*
    removes and gets the first Message struct from the queue

    @param queue pointer to the queue struct
    @param data pointer to the data buffer
    @return length of the data, 0 if queue is empty
    */
    size_t dequeue(MessageQueue *queue, char data[]);

    /*
    prints the queue

    @param queue pointer to the queue struct
    */
    void print_queue(MessageQueue *queue);
#endif // MESSAGE_QUEUE_H