#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct node {
    void* data;
    struct node* next;
} node;

typedef struct queue {
    size_t size;
    size_t memsize;
    node* head;
    node* tail;
    pthread_mutex_t* mutex;
} queue;

typedef void displayer(void*);

/**
 * @param allocSize Size of elements inserted
 * @return queue on success, NULL on error
 */
queue* create_queue(size_t memsize);

/**
 * @param q The queue
 * @param data Data to be inserted
 * @return queue on success, NULL on error
 */
queue* enqueue(queue* q, void* data);

/**
 * @param q The queue
 * @param deletedElem The element deleted
 * @return queue on success, NULL on error
 */
queue* dequeue(queue* q, void* data);

/**
 * @brief Get the front element
 * @param q The queue
 * @param data Variable to save the data
 * @return queue on success, NULL on error
 */
void front(queue* q, void* data);

/**
 * @brief Delete all the elements of the queue
 * @param q The queue
 * @return queue on success, NULL on error
 */
queue* clear_queue(queue* q);

/**
 * @brief Destroy the queue
 * This will clear, destroy and free all memory of the queue.
 * @param q Pointer to the queue
 */
void destroy_queue(queue* q);

/**
 * @param q The queue
 * @return size_t Size of queue, if queue is NULL 0 is returned.
 */
size_t get_size(queue* q);

/**
 * @brief Check if queue is empty
 *
 * @param q The queue
 * @return true if size >= 1, false otherwise,
 */
bool is_empty(queue* q);

/**
 * @brief Get the current allocation size that queue uses internally
 *
 * @param q The queue
 * @return allocation size, 0 if queue is NULL
 */
size_t get_memsize(queue* q);

/**
 * @brief Creates a deep copy of the queue
 *
 * @param src The queue to be copied
 * @return The new queue, NULL on error
 */
queue* copy_queue(queue* src);

/**
 * @brief Displays all elements of the queue using the custom displayer provided
 *
 * @param q the queue to display
 * @param display the function to call, to display indivisual items
 * @return NULL
 */
void display_queue(queue* q, displayer display);

#ifdef __cplusplus
}
#endif