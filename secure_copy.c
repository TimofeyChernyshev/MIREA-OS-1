#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include <getopt.h>
#include "caesar.h"
#include "secure_copy.h"

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

    while (1) {
        char* filename;
        int file_index;

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
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

        clock_gettime(CLOCK_REALTIME, &start_timespec);
        int status = process_file(filename, a->out_dir);
        clock_gettime(CLOCK_REALTIME, &end_timespec);

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

int process_file(char* filename, char* out_dir) {
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
        caesar(buf, enc, n);
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

double process_files(char** files, int total_files, char* out_dir, run_mode_t mode, file_stats_t** out_stats) {
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
    
    thread_args_t a = {
        .filenames = files,
        .total_files = total_files,
        .next_file_index = 0,
        .completed_files = 0,
        .out_dir = out_dir,
        .log = log,
        .stats = stats
    };
    
    pthread_mutex_init(&a.file_index_mutex, NULL);
    pthread_mutex_init(&a.counter_mutex, NULL);
    pthread_mutex_init(&a.log_mutex, NULL);
    pthread_mutex_init(&a.stats_mutex, NULL);
    
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
    clock_gettime(CLOCK_REALTIME, &total_start_timespec);
    
    pthread_t t[workers_count];
    for (int i = 0; i < workers_count; i++) {
        pthread_create(&t[i], NULL, worker, &a);
    }
    for (int i = 0; i < workers_count; i++) {
        pthread_join(t[i], NULL);
    }
    
    clock_gettime(CLOCK_REALTIME, &total_end_timespec);
    
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
    
    return total_time;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <--mode> <src_files> <dst_dir_path> <key>\n", argv[0]);
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

    caesar_key(key[0]);

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

        seq_time = process_files(files, total_files, out_dir, MODE_SEQUENTIAL, &seq_stats);
        if (seq_time < 0) {
            fprintf(stderr, "Error running sequential mode\n");
            return 1;
        }
        
        par_time = process_files(files, total_files, out_dir, MODE_PARALLEL, &par_stats);
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
        double time_taken = process_files(files, total_files, out_dir, MODE_SEQUENTIAL, &seq_stats);
        if (time_taken < 0) return 1;
        free(seq_stats);
    } else if (mode == MODE_PARALLEL) {
        double time_taken = process_files(files, total_files, out_dir, MODE_PARALLEL,  &par_stats);
        if (time_taken < 0) return 1;
        free(par_stats);
    }

    return 0;
}