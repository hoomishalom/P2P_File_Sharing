#include "../headers/message_queue.h"


void queue_init(MessageQueue *queue)
{
    queue->head = NULL;
    queue->tail = NULL;
    queue->len = 0;
}

int is_empty(MessageQueue *queue)
{
    return queue->len == 0;
}

void del_queue(MessageQueue *queue)
{
    if (queue != NULL)
    {
        while (queue->len > 0)
        {
            Message *msg = queue->head;
            queue->head = msg->next;
            queue->len--;

            free(msg);
        }
    }
}


void enqueue(MessageQueue *queue, const char *data, size_t len)
{
    Message *msg = (Message *)malloc(sizeof(Message));
    
    strcpy(msg->data, data);
    msg->len = len;
    msg->next = NULL;

    if (queue->len == 0)
    {
        queue->head = msg;
        queue->tail = msg;
        queue->len++;
    }
    else
    {
        queue->tail->next = msg;
        queue->tail = msg;
        queue->len++;
    }
}


size_t dequeue(MessageQueue *queue, char data[])
{
    if (queue -> len == 0)
    {
        return 0;
    }

    Message *msg = queue->head;
    queue->head = msg->next;
    queue->len--;

    strcpy(data, msg->data);
    size_t len = msg->len;

    free(msg);

    return len;
}

