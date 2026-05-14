#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include "caesar.h"
#include "secure_copy.h"

static void* g_secure_memory = NULL;

// Обработчик SIGSEGV
void sigsegv_handler(int sig, siginfo_t* info, void* context) {
    (void)context;
    if (g_secure_memory && info->si_addr == g_secure_memory) {
        fprintf(stderr, "\n[ERROR] Security violation: Attempt to write to protected memory at %p\n", info->si_addr);
        fprintf(stderr, "The encryption key is protected and cannot be modified!\n");
        exit(1);
    }
    fprintf(stderr, "\n[ERROR] Segmentation fault at %p\n", info->si_addr);
    exit(1);
}

// Функция для выделения защищенной памяти под ключ
char* secure_key_alloc(char key) {
    char* key_page = mmap(NULL, KEY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    
    if (key_page == MAP_FAILED) {
        perror("mmap failed");
        return NULL;
    }
    
    if (mprotect(key_page, KEY_SIZE, PROT_READ | PROT_WRITE) == -1) {
        perror("mprotect failed");
        munmap(key_page, KEY_SIZE);
        return NULL;
    }

    memcpy(key_page, &key, sizeof(char));

    if (mprotect(key_page, KEY_SIZE, PROT_READ) == -1) {
        perror("mprotect failed");
        munmap(key_page, KEY_SIZE);
        return NULL;
    }
    
    return key_page;
}

// Функция для безопасного получения ключа
char secure_key_get(char* secure_key, pthread_mutex_t* mutex) {
    if (!secure_key) return 0;

    char key;

    pthread_mutex_lock(mutex);

    if (mprotect(secure_key, KEY_SIZE, PROT_READ | PROT_WRITE) == -1) {
        perror("mprotect for read failed");
        pthread_mutex_unlock(mutex);
        return 0;
    }

    memcpy(&key, secure_key, sizeof(char));

    if (mprotect(secure_key, KEY_SIZE, PROT_READ) == -1) {
        perror("mprotect for restore failed");
        pthread_mutex_unlock(mutex);
        return 0;
    }

    pthread_mutex_unlock(mutex);
    
    return key;
}

// Функция для безопасного освобождения ключа
void secure_key_free(char** key_ptr) {
    if (!key_ptr || !*key_ptr) return;
    
    if (mprotect(*key_ptr, KEY_SIZE, PROT_READ | PROT_WRITE) == -1) {
        perror("mprotect for free failed");
    }
    
    memset(*key_ptr, 0, KEY_SIZE);
    
    msync(*key_ptr, KEY_SIZE, MS_SYNC);
    
    if (munmap(*key_ptr, KEY_SIZE) == -1) {
        perror("munmap failed");
    }
    
    *key_ptr = NULL;
}


run_mode_t parse_mode(const char* arg) {
    if (strcmp(arg, "sequential") == 0) return MODE_SEQUENTIAL;
    if (strcmp(arg, "parallel") == 0) return MODE_PARALLEL;
    
    fprintf(stderr, "Unknown mode '%s'. Available modes: sequential, parallel\n", arg);
    exit(1);
}

void print_statistics(thread_args_t* a, double total_time, run_mode_t mode) {
    printf("Mode: %s\n", mode == MODE_SEQUENTIAL ? "SEQUENTIAL" : "PARALLEL");
    printf("Total files: %d\n", a->total_files);
    printf("Successfully processed: %d\n", a->completed_files);
    printf("Total time: %.3f seconds\n", total_time);
    printf("Average time per file: %.3f seconds\n", total_time / a->total_files);
    
    printf("\nFile statistics:\n");
    printf("%-40s %12s %12s\n", "Filename", "Duration(s)", "Status");
    
    for (int i = 0; i < a->total_files; i++) {
        printf("%-40s %12.3f %12s\n", 
               a->stats[i].filename, 
               a->stats[i].duration,
               a->stats[i].status == 0 ? "OK" : "ERR");
    }
}

void* worker(void* arg) {
    thread_args_t* a = arg;

    char key = secure_key_get(a->secure_key, &a->secure_mutex);

    while (1) {
        char* filename;
        int file_index;

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 5;

        if (pthread_mutex_timedlock(&a->file_index_mutex, &ts) == ETIMEDOUT) {
            printf("Warning: mutex timeout\n");
            exit(1);
        }

        if (a->next_file_index >= a->total_files) {
            pthread_mutex_unlock(&a->file_index_mutex);
            break;
        }

        filename = a->filenames[a->next_file_index];
        file_index = a->next_file_index;
        a->next_file_index++;

        pthread_mutex_unlock(&a->file_index_mutex);

        struct timespec start_timespec;
        struct timespec end_timespec;

        clock_gettime(CLOCK_MONOTONIC, &start_timespec);
        int status = process_file(filename, a->out_dir, key);
        clock_gettime(CLOCK_MONOTONIC, &end_timespec);

        double end = end_timespec.tv_sec + end_timespec.tv_nsec / 1000000000.0;
        double start = start_timespec.tv_sec + start_timespec.tv_nsec / 1000000000.0;
        double duration = end - start;

        pthread_mutex_lock(&a->stats_mutex);
        strncpy(a->stats[file_index].filename, filename, sizeof(a->stats[file_index].filename) - 1);
        a->stats[file_index].start_time = start;
        a->stats[file_index].end_time = end;
        a->stats[file_index].duration = duration;
        a->stats[file_index].status = status;
        pthread_mutex_unlock(&a->stats_mutex);

        pthread_mutex_lock(&a->counter_mutex);
        a->completed_files++;
        pthread_mutex_unlock(&a->counter_mutex);

        pthread_mutex_lock(&a->log_mutex);
        log_write(a->log, filename, status);
        pthread_mutex_unlock(&a->log_mutex);
    }

    return NULL;
}

int process_file(char* filename, char* out_dir, char key) {
    struct stat path_stat;
    if (stat(filename, &path_stat) != 0) {
        perror("stat failed");
        return -1;
    }

    if (S_ISDIR(path_stat.st_mode)) {
        printf("Skipping directory: %s\n", filename);
        return 0;
    }

    FILE* src = fopen(filename, "rb");
    if (!src) {
        perror("fopen src");
        return -1;
    }

    char out_path[512];

    char* base = basename(filename);
    snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, base);

    FILE* dst = fopen(out_path, "wb");
    if (!dst) {
        perror("fopen dst");
        fclose(src);
        return -1;
    }

    char buf[BUF_SIZE];
    char enc[BUF_SIZE];

    size_t n;

    while ((n = fread(buf, 1, BUF_SIZE, src)) > 0) {
        caesar(buf, enc, n, key);
        fwrite(enc, 1, n, dst);
    }

    fclose(src);
    fclose(dst);

    return 0;
}

void log_write(FILE* log, char* filename, int status) {
    time_t now = time(NULL);

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log,
        "[%s] PID=%d TID=%lu FILE=%s STATUS=%s\n",
        timebuf,
        getpid(),
        pthread_self(),
        filename,
        status == 0 ? "OK" : "ERR"
    );

    fflush(log);
}

double process_files(char** files, int total_files, char* out_dir, run_mode_t mode, file_stats_t** out_stats, char key) {
    file_stats_t* stats = malloc(total_files * sizeof(file_stats_t));
    if (!stats) {
        perror("malloc");
        return -1;
    }
    
    FILE* log = fopen("log.txt", "a");
    if (!log) {
        perror("cannot open log file");
        free(stats);
        return -1;
    }

    char* secure_key = secure_key_alloc(key);
    if (!secure_key) {
        fprintf(stderr, "Failed to allocate secure memory for key\n");
        free(stats);
        fclose(log);
        return -1;
    }
    g_secure_memory = secure_key;
    
    thread_args_t a = {
        .filenames = files,
        .total_files = total_files,
        .next_file_index = 0,
        .completed_files = 0,
        .out_dir = out_dir,
        .log = log,
        .stats = stats,
        .secure_key = secure_key,
    };
    
    pthread_mutex_init(&a.file_index_mutex, NULL);
    pthread_mutex_init(&a.counter_mutex, NULL);
    pthread_mutex_init(&a.log_mutex, NULL);
    pthread_mutex_init(&a.stats_mutex, NULL);
    pthread_mutex_init(&a.secure_mutex, NULL);
    
    int workers_count;
    if (mode == MODE_SEQUENTIAL) {
        workers_count = 1;
    } else {
        if (total_files < WORKERS_COUNT) {
            workers_count = total_files;
        } else {
            workers_count = WORKERS_COUNT;
        }
    }
    printf("Using %d worker thread(s)\n", workers_count);
    
    struct timespec total_start_timespec, total_end_timespec;
    clock_gettime(CLOCK_MONOTONIC, &total_start_timespec);
    
    pthread_t t[workers_count];
    for (int i = 0; i < workers_count; i++) {
        pthread_create(&t[i], NULL, worker, &a);
    }
    for (int i = 0; i < workers_count; i++) {
        pthread_join(t[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &total_end_timespec);
    
    double total_end = total_end_timespec.tv_sec + total_end_timespec.tv_nsec / 1000000000.0;
    double total_start = total_start_timespec.tv_sec + total_start_timespec.tv_nsec / 1000000000.0;
    double total_time = total_end - total_start;
    
    printf("\nProcessed files count: %d\n", a.completed_files);
    print_statistics(&a, total_time, mode);
    
    fclose(log);
    
    *out_stats = stats;
    
    pthread_mutex_destroy(&a.file_index_mutex);
    pthread_mutex_destroy(&a.counter_mutex);
    pthread_mutex_destroy(&a.log_mutex);
    pthread_mutex_destroy(&a.stats_mutex);
    pthread_mutex_destroy(&a.secure_mutex);

    secure_key_free(&a.secure_key);
    
    return total_time;
}

#ifndef NO_MAIN

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <--mode> <src_files> <dst_dir_path> <key>\n", argv[0]);
        return 1;
    }

    struct sigaction sa;
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction failed");
        return 1;
    }

    run_mode_t mode = MODE_AUTO;
    int opt;
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "m:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                mode = parse_mode(optarg);
                break;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "No input files specified\n");
        return 1;
    }

    int total_files = argc - optind - 2;
    char** files = &argv[optind];
    char* out_dir = argv[argc - 2];
    char* key = argv[argc - 1];

    if (strlen(key) != 1) {
        fprintf(stderr, "key must be a single character\n");
        return 1;
    }
    
    char key_char = key[0];

    mkdir(out_dir, 0777);

    double seq_time = 0, par_time = 0;
    file_stats_t* seq_stats = NULL;
    file_stats_t* par_stats = NULL;

    if (mode == MODE_AUTO) {
        if (total_files < 5) {
            printf("Heuristic choose: sequential mode\n");
        } else {
            printf("Heuristic choose: parallel mode\n");
        }

        seq_time = process_files(files, total_files, out_dir, MODE_SEQUENTIAL, &seq_stats, key_char);
        if (seq_time < 0) {
            fprintf(stderr, "Error running sequential mode\n");
            return 1;
        }
        
        par_time = process_files(files, total_files, out_dir, MODE_PARALLEL, &par_stats, key_char);
        if (par_time < 0) {
            fprintf(stderr, "Error running parallel mode\n");
            free(seq_stats);
            return 1;
        }

        printf("SEQUENTIAL mode time: %.3f seconds\n", seq_time);
        printf("PARALLEL mode time:   %.3f seconds\n", par_time);
        
        free(seq_stats);
        free(par_stats);
    } else if (mode == MODE_SEQUENTIAL) {
        double time_taken = process_files(files, total_files, out_dir, MODE_SEQUENTIAL, &seq_stats, key_char);
        if (time_taken < 0) return 1;
        free(seq_stats);
    } else if (mode == MODE_PARALLEL) {
        double time_taken = process_files(files, total_files, out_dir, MODE_PARALLEL,  &par_stats, key_char);
        if (time_taken < 0) return 1;
        free(par_stats);
    }

    return 0;
}

#endif