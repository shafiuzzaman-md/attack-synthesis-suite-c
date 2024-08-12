#include "common.h"

// Buffer sizes
#define BUFFER_SIZE 256
#define COMMAND_BUFFER_SIZE 128

// Global pointers to buffers
char *user_buffer;
char *command_buffer;

// Function that chains multiple vulnerabilities from user to privileged context
void chain_vulnerabilities(int user_data) {
    char *uninitialized_var = NULL;

    printf("Starting vulnerability chaining...\n");

    // Step 1: Simulate buffer overflow in user space
    CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01_bad(user_data);

    // Step 2: Simulate uninitialized variable leading to command injection
    uninitialized_var = component_input_CWE78_bad(user_buffer);

    // Simulate overflow affecting uninitialized_var
    if (user_data >= BUFFER_SIZE) {
        uninitialized_var = command_buffer;
        strcpy(command_buffer, "echo Malicious command executed");  // This should trigger a protection violation if the segment is truly protected.
    }

    // Step 3: Execute the command injection in privileged mode
    component_privileged_CWE78_bad();
}

int main() {
    initialize_system();

    // Allocate memory for user and command buffers using the memory model
    user_buffer = (char*) allocateMemorySegment(BUFFER_SIZE, DATA_SEGMENT, 1, 1, 0); // Readable, Writable
    command_buffer = (char*) allocateMemorySegment(COMMAND_BUFFER_SIZE, PROTECTED_SEGMENT, 1, 0, 0); // Readable, Non-Writable, Non-Executable

    if (user_buffer == NULL || command_buffer == NULL) {
        printf("Error: Memory allocation failed.\n");
        return 1;
    }

    int malicious_input = 15;  // Simulated user input that triggers the overflow
    chain_vulnerabilities(malicious_input);

    // Free the allocated memory
    freeMemorySegment(user_buffer);
    freeMemorySegment(command_buffer);

    return 0;
}
