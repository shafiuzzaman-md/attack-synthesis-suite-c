#include "common.h"

// Attack Goal: Write in Protected Segment
// Attacke scenerio: Exploit a buffer overflow in the Data Segment to inject malicious code
// into the Code Segment, then execute it to modify the Protected Segment.

void chain_vulnerabilities(int user_data) {

    printf("Starting vulnerability chaining...\n");

    // Step 1: Buffer Overflow in Data Segment
    // Overflow `user_buffer` to inject a command into the Code Segment.
    u_CWE121_CWE129_large_01_bad(user_data);

    // Step 2: Execute command in the Code Segment
    // The injected command in `command_buffer` is executed, which modifies the Protected Segment.
    u_execute_command(command_buffer);
}

int main() {
    // Initialize system and allocate buffers
    initialize_system();

    // Simulate input that triggers the buffer overflow
    int malicious_input = 11;  // crafted input causes overflow to reach `command_buffer`
    chain_vulnerabilities(malicious_input);

    return 0;
}
