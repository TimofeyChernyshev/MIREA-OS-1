#include "rc4.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

struct rc4_state {
    unsigned char S[256];
    int i;
    int j;
};

static void swap(unsigned char* a, unsigned char* b) {
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

rc4_state_t* rc4_init(const unsigned char* key, int key_len) {
    size_t size = sizeof(struct rc4_state);
    
    struct rc4_state* state = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (state == MAP_FAILED) {
        perror("mmap rc4 state");
        return NULL;
    }

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

    if (mprotect(state, size, PROT_NONE) == -1) {
        perror("mprotect rc4 state");
        munmap(state, size);
        return NULL;
    }

    return state;
}

void rc4_crypt(rc4_state_t* state_ptr, unsigned char* data, size_t len) {
    struct rc4_state* state = (struct rc4_state*)state_ptr;
    size_t size = sizeof(struct rc4_state);

    mprotect(state, size, PROT_WRITE);
    
    for (size_t n = 0; n < len; n++) {
        state->i = (state->i + 1) & 0xFF;
        state->j = (state->j + state->S[state->i]) & 0xFF;
        
        swap(&state->S[state->i], &state->S[state->j]);
        
        unsigned char k = state->S[(state->S[state->i] + state->S[state->j]) & 0xFF];
        data[n] ^= k;
    }

    mprotect(state, size, PROT_NONE);
}

void rc4_cleanup(rc4_state_t** state_ptr) {
    if (!state_ptr || !*state_ptr) return;
    
    struct rc4_state* state = (struct rc4_state*)*state_ptr;
    size_t size = sizeof(struct rc4_state);
    
    mprotect(state, size, PROT_WRITE);
    
    memset(state, 0, size);
    msync(state, size, MS_SYNC);
    
    munmap(state, size);
    
    *state_ptr = NULL;
}