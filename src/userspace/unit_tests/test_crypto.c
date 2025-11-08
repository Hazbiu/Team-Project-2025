#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>

void test_hash_calculation(void) {
    printf("=== Testing Hash Calculations ===\n");
    
    const char *test_data = "dm-verity-test-data";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)test_data, strlen(test_data), hash);
    
    int all_zero = 1;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (hash[i] != 0) all_zero = 0;
    }
    assert(!all_zero);
    printf("✓ Hash calculation: PASSED\n");
}

int main() {
    test_hash_calculation();
    printf("=== All Crypto Tests PASSED ===\n");
    return 0;
}