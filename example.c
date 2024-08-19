#include "common.h"

// Function that chains multiple vulnerabilities from user to privileged context
void chain_vulnerabilities(int user_data) {
    // Attack Goal: Write in Protected Segment
    // Attacke scenerio: Exploit a buffer overflow in the Data Segment to inject malicious code
    // into the Code Segment, then execute it to modify the Protected Segment.

    printf("Starting vulnerability chaining...\n");

    // Step 1: Buffer Overflow in Data Segment
    // Overflow `user_buffer` to inject a command into the Code Segment.
    u_CWE121_CWE129_large_01_bad(user_data, user_buffer);

    // Step 2: Execute the injected command in the Code Segment
    // The injected command in `command_buffer` is executed, which modifies the Protected Segment.
    execute_command(command_buffer);
}

int main() {
    // Initialize system and allocate buffers
    initialize_system();
    allocate_all_buffers();

    // Simulate input that triggers the buffer overflow
    int malicious_input = BUFFER_SIZE + COMMAND_BUFFER_SIZE;  // Causes overflow to reach `command_buffer`
    chain_vulnerabilities(malicious_input);

    // Free allocated memory
    free_all_buffers();

    return 0;
}
