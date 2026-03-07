#pragma once

#define BUF_SIZE 4096

#include "queue.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

typedef struct {
    char data[BUF_SIZE];
    size_t len;
    bool is_last;
} buffer_t;

typedef struct {
    FILE* src_file;
    FILE* dst_file;
    queue* q;
} thread_args_t;

void* reader_thread(void* arg);
void* writer_thread(void* arg);