#include "rc4.h"

#include <string.h>

static void swap(unsigned char* a, unsigned char* b) {
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

void rc4_init(rc4_state_t* state, const unsigned char* key, int key_len) {
    state->i = 0;
    state->j = 0;

    for (int i = 0; i < 256; i++) {
        state->S[i] = (unsigned char)i;
    }

    int j = 0;

    for (int i = 0; i < 256; i++) {
        j = (j + state->S[i] + key[i % key_len]) & 0xFF;

        swap(&state->S[i], &state->S[j]);
    }
}

void rc4_crypt(rc4_state_t* state, unsigned char* data, size_t len) {
    for (size_t n = 0; n < len; n++) {
        state->i = (state->i + 1) & 0xFF;
        state->j = (state->j + state->S[state->i]) & 0xFF;

        swap(&state->S[state->i], &state->S[state->j]);

        unsigned char k = state->S[(state->S[state->i] + state->S[state->j]) & 0xFF];

        data[n] ^= k;
    }
}

void rc4_cleanup(rc4_state_t* state) {
    memset(state, 0, sizeof(rc4_state_t));
}