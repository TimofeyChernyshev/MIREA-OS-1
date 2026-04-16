#pragma once

#define BUF_SIZE 4096
#define TIMEOUT_SEC 5
#define WORKERS_COUNT 4

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

typedef enum {
    MODE_SEQUENTIAL,
    MODE_PARALLEL,
    MODE_AUTO
} run_mode_t;

typedef struct {
    char filename[512];
    double start_time;
    double end_time;
    double duration;
    int status;
} file_stats_t;

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

    file_stats_t* stats;
    pthread_mutex_t stats_mutex;
} thread_args_t;

void* worker(void* arg);
int process_file(char* filename, char* out_dir);
void log_write(FILE* log, char* filename, int status);
void print_statistics(thread_args_t* a, double total_time, run_mode_t mode);
run_mode_t parse_mode(const char* arg);
double process_files(char** files, int total_files, char* out_dir, run_mode_t mode, file_stats_t** out_stats);