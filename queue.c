#include "queue.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

node* create_node(void* data, size_t memsize) {
    node* new_node = (node*)malloc(sizeof(node));
    if (new_node == NULL)
        return NULL;

    new_node->data = malloc(memsize);
    if (new_node->data == NULL) {
        free(new_node);
        return NULL;
    }

    memcpy(new_node->data, data, memsize);
    new_node->next = NULL;

    return new_node;
}

queue* create_queue(size_t memsize) {
    queue* q = (queue*)malloc(sizeof(queue));
    if (q == NULL)
        return NULL;

    q->memsize = memsize;
    q->size = 0;
    q->head = NULL;
    q->tail = NULL;

    return q;
}

queue* enqueue(queue* q, void* data) {

    pthread_mutex_lock(q->mutex);
    if (q == NULL)
        return NULL;

    node* new_node = create_node(data, q->memsize);
    if (new_node == NULL) {
        return NULL;
    }

    if (q->size == 0) {
        q->head = q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }

    q->size++;
    pthread_mutex_unlock(q->mutex);
    return q;
}

queue* dequeue(queue* q, void* data) {
    pthread_mutex_lock(q->mutex);
    if (q == NULL)
        return NULL;
    if (q->size == 0)
        return NULL;

    node* to_delete = q->head;
    if (q->size == 1) {
        memcpy(data, to_delete->data, q->memsize);
        free(to_delete->data);
        free(to_delete);
        q->head = q->tail = NULL;
        q->size--;
        pthread_mutex_unlock(q->mutex);
        return q;
    }

    q->head = q->head->next;
    memcpy(data, to_delete->data, q->memsize);
    free(to_delete->data);
    free(to_delete);
    q->size--;

    pthread_mutex_unlock(q->mutex);
    return q;
}

void front(queue* q, void* data) {
    if (q == NULL)
        return;

    if (q->size == 0)
        return;

    memcpy(data, q->head->data, q->memsize);
}

queue* clear_queue(queue* q) {
    pthread_mutex_lock(q->mutex);
    if (q == NULL)
        return NULL;

    while (!is_empty(q)) {
        node* temp = q->head;
        q->head = q->head->next;
        free(temp->data);
        free(temp);
        q->size--;
    }
    pthread_mutex_unlock(q->mutex);
    return q;
}

size_t get_size(queue* q) {
    pthread_mutex_lock(q->mutex);
    if (q == NULL) {
        return 0;
    }
    pthread_mutex_unlock(q->mutex);
    return q->size;
}

bool is_empty(queue* q) {
    return q->size == 0 ? true : false;
}

size_t get_memsize(queue* q) {
    if (q == NULL) {
        return 0;
    }
    return q->memsize;
}

queue* copy_queue(queue* src) {
    pthread_mutex_lock(src->mutex);

    if (src == NULL) {
        return NULL;
    }

    queue* new_queue = create_queue(src->memsize);
    if (new_queue == NULL) {
        return NULL;
    }

    // Iterate through original queue and copy nodes
    node* current = src->head;
    while (current != NULL) {
        enqueue(new_queue, current->data);
        current = current->next;
    }
    pthread_mutex_unlock(src->mutex);
    return new_queue;
}

void destroy_queue(queue* q) {
    clear_queue(q);
    pthread_mutex_destroy(q->mutex); 
    free(q->mutex);
    free(q);
}

void display_queue(queue* q, displayer display) {
    node* current = q->head;

    while (current) {
        display(current->data);
        current = current->next;
    }
}