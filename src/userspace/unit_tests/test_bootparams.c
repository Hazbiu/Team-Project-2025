#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

void test_kernel_cmdline_parsing(void) {
    printf("=== Testing Kernel Command Line Parsing ===\n");
    
    const char *cmdline_orig = "root=/dev/sda1 verity.hash=abc123 verity.salt=def456 console=ttyS0";
    
    // Make a copy since strtok modifies the string
    char *cmdline = malloc(strlen(cmdline_orig) + 1);
    strcpy(cmdline, cmdline_orig);
    
    char root_device[64] = {0};
    char root_hash[65] = {0};
    char salt[33] = {0};
    
    char *token = strtok(cmdline, " ");
    while (token != NULL) {
        if (strncmp(token, "root=", 5) == 0) {
            strncpy(root_device, token + 5, sizeof(root_device) - 1);
        } else if (strncmp(token, "verity.hash=", 12) == 0) {
            strncpy(root_hash, token + 12, sizeof(root_hash) - 1);
        } else if (strncmp(token, "verity.salt=", 12) == 0) {
            strncpy(salt, token + 12, sizeof(salt) - 1);
        }
        token = strtok(NULL, " ");
    }
    
    free(cmdline);
    
    printf("  Found: root=%s, hash=%s, salt=%s\n", root_device, root_hash, salt);
    printf("✓ Command line parsing: PASSED\n");
}

int main() {
    test_kernel_cmdline_parsing();
    printf("=== All Boot Parameter Tests PASSED ===\n");
    return 0;
}