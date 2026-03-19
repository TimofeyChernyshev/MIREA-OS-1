// 3 Обновка /secure_copy file1.txt file2.txt ... fileN.txt /dir key
// 3 потока (1 поток - чтение/запись/зашифрование)
// в /dir зашифрованные файлы, которые имеют то же название что и исходник
// в файл log.txt пишем логи туда же откуда запускаем код 
// время, имя файла, ID процесса
// trylock или timelock (5 сек, если > то выводим предупреждение и завершаем)
// 1) файлы копируются
// 2) на C
// 3) нет дубликатов (потоки не работают с одними и теми же файлами)
// 4) файлы корректно расшифровываются

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include "caesar.h"
#include "secure_copy.h"

void* worker(void* arg) {
    thread_args_t* a = arg;

    while (1) {
        char* filename;

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
        a->next_file_index++;

        pthread_mutex_unlock(&a->file_index_mutex);

        int status = process_file(filename, a->out_dir);

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

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <src_files> <dst_dir_path> <key>\n", argv[0]);
        return 1;
    }

    int total_files = argc - 3;
    char** files = &argv[1];

    char* out_dir = argv[argc - 2];
    char* key = argv[argc - 1];

    // signal(SIGINT, sigint_handler);

    caesar_key(key[0]);

    mkdir(out_dir, 0777);

    FILE* log = fopen("log.txt", "a");

    thread_args_t a = {
        .filenames = files,
        .total_files = total_files,
        .next_file_index = 0,
        .completed_files = 0,
        .out_dir = out_dir,
        .log = log
    };

    pthread_mutex_init(&a.file_index_mutex, NULL);
    pthread_mutex_init(&a.counter_mutex, NULL);
    pthread_mutex_init(&a.log_mutex, NULL);

    pthread_t t[3];

    for (int i = 0; i < 3; i++) {
        pthread_create(&t[i], NULL, worker, &a);
    }

    for (int i = 0; i < 3; i++) {
        pthread_join(t[i], NULL);
    }

    printf("Processed files count: %d\n", a.completed_files);

    fclose(log);

    return 0;
}