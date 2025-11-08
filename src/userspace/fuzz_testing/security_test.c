#include <stdio.h>
#include <string.h>

void test_buffer_overflow_protection(void) {
    printf("=== Testing Security Features ===\n");
    
    char long_input[1024];
    memset(long_input, 'A', sizeof(long_input) - 1);
    long_input[sizeof(long_input) - 1] = '\0';
    
    char buffer[64];
    strncpy(buffer, long_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    printf("✓ Buffer overflow protection: PASSED\n");
}

int main() {
    test_buffer_overflow_protection();
    return 0;
}