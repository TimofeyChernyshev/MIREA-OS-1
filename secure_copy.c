#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <limits.h>
#include "rc4.h"
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

void queue_init(write_queue_t* q) {
    q->head = q->tail = NULL;
    q->finished = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

void queue_push(write_queue_t* q, write_job_t* job) {
    job->next = NULL;

    pthread_mutex_lock(&q->mutex);

    if (!q->tail) {
        q->head = q->tail = job;
    } else {
        q->tail->next = job;
        q->tail = job;
    }

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

write_job_t* queue_pop(write_queue_t* q) {
    pthread_mutex_lock(&q->mutex);

    while (!q->head && !q->finished) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    if (!q->head && q->finished) {
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }

    write_job_t* job = q->head;
    q->head = job->next;

    if (!q->head)
        q->tail = NULL;

    pthread_mutex_unlock(&q->mutex);
    return job;
}

void queue_finish(write_queue_t* q) {
    pthread_mutex_lock(&q->mutex);
    q->finished = 1;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

// Функция для выделения защищенной памяти под ключ
char* secure_key_alloc(char* key) {
    char* key_page = mmap(NULL, KEY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    
    if (key_page == MAP_FAILED) {
        perror("mmap failed");
        return NULL;
    }
    
    memset(key_page, 0, KEY_SIZE);
    size_t key_len = strlen(key);
    memcpy(key_page, key, key_len > KEY_SIZE ? KEY_SIZE : key_len);

    if (mprotect(key_page, KEY_SIZE, PROT_READ) == -1) {
        perror("mprotect failed");
        munmap(key_page, KEY_SIZE);
        return NULL;
    }
    
    return key_page;
}

// Функция для безопасного получения ключа
char* secure_key_get(char* secure_key, pthread_mutex_t* mutex) {
    // __thread чтобы каждый поток получал свою копию переменной
    static __thread char local_key[KEY_SIZE]; 

    pthread_mutex_lock(mutex);

    if (mprotect(secure_key, KEY_SIZE, PROT_READ | PROT_WRITE) == -1) {
        perror("mprotect failed");
        pthread_mutex_unlock(mutex);
        return NULL;
    }

    memcpy(local_key, secure_key, KEY_SIZE);

    if (mprotect(secure_key, KEY_SIZE, PROT_READ) == -1) {
        perror("mprotect restore failed");
        pthread_mutex_unlock(mutex);
        return NULL;
    }

    pthread_mutex_unlock(mutex);

    return local_key;
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

    char* key = secure_key_get(a->secure_key, &a->secure_mutex);

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
        int status = process_file(filename, key, a->queue);
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

void* writer_thread(void* arg) {
    thread_args_t* a = arg;
    write_queue_t* q = a->queue;

    while (1) {
        write_job_t* job = queue_pop(q);
        if (!job) break;

        pthread_mutex_lock(&a->container_mutex);

        write(a->container_fd, &job->header, sizeof(job->header));
        write(a->container_fd, job->filename, job->header.filename_len);
        write(a->container_fd, job->data, job->data_size);

        pthread_mutex_unlock(&a->container_mutex);

        free(job->filename);
        free(job->data);
        free(job);
    }

    return NULL;
}

int process_file(char* filename, char* key, write_queue_t* queue) {
    struct stat path_stat;
    if (stat(filename, &path_stat) != 0) {
        perror("stat failed");
        return -1;
    }

    FILE* src = fopen(filename, "rb");
    if (!src) {
        perror("fopen src");
        return -1;
    }

    file_entry_header_t header;
    memset(&header, 0, sizeof(header));

    header.file_size = (uint32_t)path_stat.st_size;
    header.filename_len = (uint32_t)strlen(filename);

    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        perror("urandom");
        fclose(src);
        return -1;
    }

    fread(header.salt, 1, SALT_SIZE, urandom);
    fclose(urandom);

    unsigned char derived_key[KEY_SIZE + SALT_SIZE];
    memset(derived_key, 0, sizeof(derived_key));
    size_t key_len = strnlen(key, KEY_SIZE);
    memcpy(derived_key, key, key_len);
    memcpy(derived_key + key_len, header.salt, SALT_SIZE);

    rc4_state_t* rc4 = rc4_init(derived_key, strlen(key) + SALT_SIZE);
    if (!rc4) {
        fclose(src);
        return -1;
    }

    memset(derived_key, 0, sizeof(derived_key));

    uint8_t* encrypted_data = malloc(header.file_size);
    if (!encrypted_data) {
        perror("malloc encrypted_data");
        rc4_cleanup(&rc4);
        fclose(src);
        return -1;
    }

    size_t total_read = 0;
    size_t n;

    while ((n = fread(encrypted_data + total_read, 1, header.file_size - total_read, src)) > 0) {
        rc4_crypt(rc4, encrypted_data + total_read, n);
        total_read += n;
    }

    fclose(src);
    rc4_cleanup(&rc4);

    if (total_read != header.file_size) {
        fprintf(stderr, "read mismatch: expected %u got %zu\n", header.file_size, total_read);
        free(encrypted_data);
        return -1;
    }

    write_job_t* job = malloc(sizeof(write_job_t));
    if (!job) {
        perror("malloc job");
        free(encrypted_data);
        return -1;
    }

    job->header = header;

    job->filename = strdup(filename);
    if (!job->filename) {
        perror("strdup");
        free(encrypted_data);
        free(job);
        return -1;
    }

    job->data = encrypted_data;
    job->data_size = header.file_size;

    job->next = NULL;

    queue_push(queue, job);

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

double process_files(char** files, int total_files, int container_fd, run_mode_t mode, file_stats_t** out_stats, char* key) {
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
        .log = log,
        .stats = stats,
        .secure_key = secure_key,
        .container_fd = container_fd
    };

    write_queue_t write_queue;
    queue_init(&write_queue);
    a.queue = &write_queue; 

    pthread_t writer_tid;
    pthread_create(&writer_tid, NULL, writer_thread, &a);
    
    pthread_mutex_init(&a.file_index_mutex, NULL);
    pthread_mutex_init(&a.counter_mutex, NULL);
    pthread_mutex_init(&a.log_mutex, NULL);
    pthread_mutex_init(&a.stats_mutex, NULL);
    pthread_mutex_init(&a.secure_mutex, NULL);
    pthread_mutex_init(&a.container_mutex, NULL);
    
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
    pthread_mutex_destroy(&a.container_mutex);

    secure_key_free(&a.secure_key);
    queue_finish(&write_queue);
    pthread_join(writer_tid, NULL);
    
    return total_time;
}

void init_file_list(file_list_t* list) {
    list->count = 0;
    list->capacity = 16;

    list->items = malloc(sizeof(char*) * list->capacity);

    if (!list->items) {
        perror("malloc");
        exit(1);
    }
}

void add_file_to_list(file_list_t* list, const char* path) {
    if (list->count >= list->capacity) {
        list->capacity *= 2;

        char** tmp = realloc(list->items, sizeof(char*) * list->capacity);

        if (!tmp) {
            perror("realloc");
            exit(1);
        }

        list->items = tmp;
    }

    list->items[list->count] = strdup(path);

    if (!list->items[list->count]) {
        perror("strdup");
        exit(1);
    }

    list->count++;
}

void recursive_collect(const char* path, file_list_t* list) {
    struct stat st;

    if (lstat(path, &st) == -1) {
        perror("lstat");
        return;
    }

    if (S_ISREG(st.st_mode)) {
        add_file_to_list(list, path);
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        return;
    }

    DIR* dir = opendir(path);

    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        recursive_collect(full_path, list);
    }

    closedir(dir);
}

void free_file_list(file_list_t* list) {
    for (int i = 0; i < list->count; i++) {
        free(list->items[i]);
    }

    free(list->items);
}

int mkdir_p(const char* path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }

    return mkdir(tmp, 0755);
}

void create_parent_dirs(const char* filepath) {
    char tmp[PATH_MAX];

    snprintf(tmp, sizeof(tmp), "%s", filepath);

    char* last_slash = strrchr(tmp, '/');

    if (!last_slash) {
        return;
    }

    *last_slash = '\0';

    mkdir_p(tmp);
}

int list_container(const char* container_path) {
    FILE* f = fopen(container_path, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    while (1) {
        file_entry_header_t header;

        size_t r = fread(&header, sizeof(header), 1, f);
        if (r == 0) {
            break;
        }

        char filename[1024];

        memset(filename, 0, sizeof(filename));

        fread(filename, 1, header.filename_len, f);

        printf("FILE: %s SIZE: %u\n", filename, header.file_size);

        fseek(f, header.file_size, SEEK_CUR);
    }

    fclose(f);

    return 0;
}

int extract_container(const char* container_path, const char* output_dir, const char* key) {
    FILE* f = fopen(container_path, "rb");

    if (!f) {
        perror("fopen container");
        return -1;
    }

    while (1) {
        file_entry_header_t header;

        size_t r = fread(&header, sizeof(header), 1, f);
        if (r == 0) {
            break;
        }

        char filename[PATH_MAX];
        memset(filename, 0, sizeof(filename));
        if (header.filename_len >= sizeof(filename)) {
            fprintf(stderr, "filename too long\n");
            fclose(f);
            return -1;
        }

        r = fread(filename, 1, header.filename_len, f);

        if (r != header.filename_len) {
            fprintf(stderr, "failed to read filename\n");
            fclose(f);
            return -1;
        }

        char full_output[PATH_MAX];
        snprintf(full_output, sizeof(full_output), "%s/%s", output_dir, filename);
        create_parent_dirs(full_output);

        FILE* out = fopen(full_output, "wb");
        if (!out) {
            perror("fopen output");
            fclose(f);
            return -1;
        }

        size_t key_len = strnlen(key, KEY_SIZE);
        unsigned char derived_key[KEY_SIZE + SALT_SIZE];
        memset(derived_key, 0, sizeof(derived_key));
        memcpy(derived_key, key, key_len);
        memcpy(derived_key + key_len, header.salt, SALT_SIZE);

        rc4_state_t* rc4 = rc4_init(derived_key, key_len + SALT_SIZE);

        memset(derived_key, 0, sizeof(derived_key));

        if (!rc4) {
            fclose(out);
            fclose(f);
            return -1;
        }

        unsigned char buf[BUF_SIZE];
        uint32_t remaining = header.file_size;

        while (remaining > 0) {
            size_t chunk = remaining > BUF_SIZE ? BUF_SIZE : remaining;

            r = fread(buf, 1, chunk, f);

            if (r != chunk) {
                fprintf(stderr, "failed to read encrypted data\n");

                rc4_cleanup(&rc4);
                fclose(out);
                fclose(f);

                return -1;
            }

            rc4_crypt(rc4, buf, chunk);

            size_t written = fwrite(buf, 1, chunk, out);

            if (written != chunk) {
                perror("fwrite");

                rc4_cleanup(&rc4);

                fclose(out);
                fclose(f);

                return -1;
            }

            remaining -= chunk;
        }

        rc4_cleanup(&rc4);

        fclose(out);

        printf("Extracted: %s\n", full_output);
    }

    fclose(f);

    return 0;
}

#ifndef NO_MAIN

int main(int argc, char* argv[]) {
    struct sigaction sa;
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction failed");
        return 1;
    }

    run_mode_t mode = MODE_SEQUENTIAL;
    int opt;
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"add", no_argument, 0, 'a'},
        {"list", no_argument, 0, 'l'},
        {"extract", no_argument, 0, 'x'},
        {0, 0, 0, 0}
    };

    bool add_mode = false;
    bool list_mode = false;
    bool extract_mode = false;

    while ((opt = getopt_long(argc, argv, "m:alx", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                mode = parse_mode(optarg);
                break;
            case 'a':
                add_mode = true;
                break;
            case 'l':
                list_mode = true;
                break;
            case 'x':
                extract_mode = true;
                break;
        }
    }

    if (list_mode) {
        if (optind >= argc) {
            fprintf(stderr, "Container path required\n");
            return 1;
        }

        return list_container(argv[optind]);
    }

    if (extract_mode) {
        if (argc - optind < 3) {
            fprintf(
                stderr,
                "Usage: --extract <container> <output_dir> <key>\n"
            );

            return 1;
        }

        return extract_container(
            argv[optind],
            argv[optind + 1],
            argv[optind + 2]
        );
    }

    if (add_mode) {
        if (argc - optind < 3) {
            fprintf(
                stderr,
                "Usage: --add <files...> <container> <key>\n"
            );
            return 1;
        }

        file_list_t list;
        init_file_list(&list);
        int input_count = argc - optind - 2;

        for (int i = 0; i < input_count; i++) {
            recursive_collect(argv[optind + i], &list);
        }

        if (list.count == 0) {
            fprintf(stderr, "No files found\n");
            free_file_list(&list);
            return 1;
        }

        char* container_path = argv[argc - 2];
        char* key = argv[argc - 1];

        int fd = open(container_path, O_CREAT | O_WRONLY, 0666);

        if (fd < 0) {
            perror("open container");
            free_file_list(&list);
            return 1;
        }

        file_stats_t* stats = NULL;

        double time_taken = process_files(list.items, list.count, fd, mode, &stats, key);

        close(fd);
        free(stats);
        free_file_list(&list);

        if (time_taken < 0) {
            return 1;
        }

        return 0;
    }

    return 0;
}

#endif