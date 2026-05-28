#pragma once

#define BUF_SIZE 4096
#define TIMEOUT_SEC 5
#define WORKERS_COUNT 4
#define KEY_SIZE 256
#define SALT_SIZE 16

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
    uint32_t file_size;
    uint32_t filename_len;
    unsigned char salt[SALT_SIZE];
} file_entry_header_t;

typedef struct {
    char** items;
    int count;
    int capacity;
} file_list_t;

typedef struct {
    char** filenames;
    int total_files;

    int next_file_index;
    pthread_mutex_t file_index_mutex;

    int completed_files;
    pthread_mutex_t counter_mutex;

    FILE* log;
    pthread_mutex_t log_mutex;

    file_stats_t* stats;
    pthread_mutex_t stats_mutex;

    char* secure_key;  // Указатель на защищенную область памяти
    pthread_mutex_t secure_mutex;

    int container_fd;
    pthread_mutex_t container_mutex;

    off_t current_offset;
    pthread_mutex_t offset_mutex;
} thread_args_t;

void* worker(void* arg);
int process_file(char* filename, char* key, int fd, off_t base_offset);
void log_write(FILE* log, char* filename, int status);
void print_statistics(thread_args_t* a, double total_time, run_mode_t mode);
run_mode_t parse_mode(const char* arg);
double process_files(char** files, int total_files, int container_fd, run_mode_t mode, file_stats_t** out_stats, char* key);

char* secure_key_alloc(char* key);
void secure_key_free(char** key_ptr);
char* secure_key_get(char* secure_key, pthread_mutex_t* mutex);
void sigsegv_handler(int sig, siginfo_t* info, void* context);

int list_container(const char* container_path);