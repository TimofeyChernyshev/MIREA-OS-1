#ifndef RC4_H
#define RC4_H

#include <stddef.h>

typedef struct rc4_state rc4_state_t;

rc4_state_t* rc4_init(const unsigned char* key, int key_len);

void rc4_crypt(rc4_state_t* state_ptr, unsigned char* data, size_t len);

void rc4_cleanup(rc4_state_t** state_ptr);

#endif