#ifndef RC4_H
#define RC4_H

#include <stddef.h>

typedef struct {
    unsigned char S[256];
    int i;
    int j;
} rc4_state_t;

void rc4_init(rc4_state_t* state, const unsigned char* key, int key_len);

void rc4_crypt(rc4_state_t* state, unsigned char* data, size_t len);

void rc4_cleanup(rc4_state_t* state);

#endif