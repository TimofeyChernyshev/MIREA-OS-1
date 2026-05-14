#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "secure_copy.h"

int main() {
    printf("TEST: SIGSEGV Handler for Protected Memory\n");
    
    char key_char = 'A';
    char* secure_key = secure_key_alloc(key_char);
    if (!secure_key) {
        fprintf(stderr, "Failed to allocate secure memory for key\n");
        return 1;
    }
    
    printf("Secure memory allocated at %p\n", (void*)secure_key);
    printf("Key: '%c' stored in protected memory\n", key_char);
    
    printf("Attempting to write to protected memory...\n");
    
    secure_key[0] = 'B';
    
    printf("\nTEST FAILED: Write succeeded! Memory protection is NOT working!\n");
    
    secure_key_free(&secure_key);
    return 1;
}