#include <string.h>
#include <unistd.h>
#include "caesar.h"
#include "secure_copy.h"

volatile sig_atomic_t keep_running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

void* writer_thread(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
    buffer_t *buffer;
    char processed[BUF_SIZE];

    while (keep_running || get_size(args->q) > 0) {
        if (get_size(args->q) == 0) {
            sched_yield();
            continue;
        }
        
        dequeue(args->q, &buffer);
        caesar(buffer->data, processed, buffer->len);
        fwrite(processed, 1, buffer->len, args->dst_file);
        
        if (buffer->is_last) {
            printf("\n");
            free(buffer);
            break; 
        }
        free(buffer);
    }

    return NULL;
}

void* reader_thread(void* arg) {
    thread_args_t *args = (thread_args_t*) arg;

    while (keep_running) {
        buffer_t *buffer = malloc(sizeof(buffer_t));
        buffer->len = fread(
            buffer->data,
            1,
            sizeof(buffer->data),
            args->src_file
        );

        buffer->is_last = (buffer->len < sizeof(buffer->data));

        enqueue(args->q, &buffer);

        if (buffer->is_last) {
            break;
        }
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <src_path> <dst_path> <key>\n", argv[0]);
        return 1;
    }

    char* src_path = argv[1];
    char* dst_path = argv[2];
    char* key = argv[3];

    signal(SIGINT, sigint_handler);

    caesar_key(key[0]);

    queue* q = create_queue(sizeof(buffer_t*));
    q->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(q->mutex, NULL);

    FILE* src = fopen(src_path, "rb");
    if (!src) {
        perror("cannot open src");
        destroy_queue(q);
        return 1;
    }

    FILE* dst = fopen(dst_path, "wb");
    if (!dst) {
        perror("cannot open dst");
        fclose(src);
        destroy_queue(q);
        return 1;
    }

    thread_args_t args = {
        .src_file = src,
        .dst_file = dst,
        .q = q
    };
    pthread_t thread_reader, thread_writer;
    pthread_create(&thread_reader, NULL, reader_thread, &args);
    pthread_create(&thread_writer, NULL, writer_thread, &args);
    
    pthread_join(thread_reader, NULL);
    pthread_join(thread_writer, NULL);

    fclose(src);
    fclose(dst);
    destroy_queue(q);

    if (!keep_running) {
        unlink(dst_path);
        printf("Операция прервана пользователем\n");
        return 1;
    }

    return 0;
}