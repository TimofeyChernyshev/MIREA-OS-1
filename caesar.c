#include "caesar.h"

static char global_key = 0;

void caesar(void* src, void* dst, int len) {
    char* src_bytes = (char*)src;
    char* dst_bytes = (char*)dst;

    for (int i = 0; i < len; i++) {
        dst_bytes[i] = src_bytes[i] ^ global_key;
    }
}

void caesar_key(char key) {
    global_key = key;
}