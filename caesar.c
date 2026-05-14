#include "caesar.h"

void caesar(void* src, void* dst, int len, char key) {
    char* src_bytes = (char*)src;
    char* dst_bytes = (char*)dst;

    for (int i = 0; i < len; i++) {
        dst_bytes[i] = src_bytes[i] ^ key;
    }
}