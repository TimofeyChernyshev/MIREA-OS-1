#pragma once

#define BUF_SIZE 4096
#define TIMEOUT_SEC 5

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

typedef struct {
    char** filenames;
    int total_files;

    int next_file_index;
    pthread_mutex_t file_index_mutex;

    char* out_dir;

    int completed_files;
    pthread_mutex_t counter_mutex;

    FILE* log;
    pthread_mutex_t log_mutex;
} thread_args_t;

void* worker(void* arg);
int process_file(char* filename, char* out_dir);
void log_write(FILE* log, char* filename, int status);