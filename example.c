#include "common.h"

// Function declarations
void component_input_CWE121_bad(int user_data);
char* component_input_CWE78_bad(char *user_data);
void component_privileged_CWE78_bad();

void chain_vulnerabilities(int user_data) {
    char *uninitialized_var = NULL;

    printf("Starting vulnerability chaining...\n");

    // Step 1: Exploit the buffer overflow
    component_input_CWE121_bad(user_data);

    // Step 2: Use uninitialized variable
    uninitialized_var = component_input_CWE78_bad((char*)buffer);

    // Simulate overflow affecting uninitialized_var
    if (user_data >= BUFFER_SIZE) {
        uninitialized_var = (char*)command_buffer;
        strcpy(command_buffer, "echo Malicious command executed");
    }

    // Step 3: Execute the command injection in privileged mode
    component_privileged_CWE78_bad();
}

int main() {
    initialize_system();

    int malicious_input = 15; // Value that causes overflow and exploit chain
    chain_vulnerabilities(malicious_input);

    return 0;
}
