#include "common.h"
#define OMITGOOD
#include "testcases/CWE78_OS_Command_Injection/s02/CWE78_OS_Command_Injection__char_console_system_01.c"

// Global variable to track the current execution mode, defined in user_accessible.c
ExecutionMode current_mode = PRIVILEGED_MODE;

// Function to set the execution mode
void set_mode(ExecutionMode mode) {
    current_mode = mode;
}

// Function to get the current execution mode
ExecutionMode get_mode() {
    return current_mode;
}

// Execute a specific command stored in the code segment
void execute_command_privileged(int command_number) {
     if (current_mode != PRIVILEGED_MODE) {
        printf("ERROR: Attempt to execute privileged command in non-privileged mode.\n");
        return;
    }

    // Retrieve the base address of the command buffer in the code segment
    char *command_buffer = (char*) getMemorySegmentBase(CODE_SEGMENT);
    klee_make_symbolic(&command_buffer, sizeof(command_buffer), "command_buffer");
    if (!command_buffer) {
        printf("ERROR: Command buffer in the code segment is not initialized.\n");
        return;
    }
    // Assuming each command is of fixed length and stored sequentially
    int command_size = 256;  // Example fixed size for each command
    char *command = command_buffer + command_number * command_size;
    klee_assert(!EXECUTE_COMMAND);
    // Null-terminate the selected command for execution
    char command_copy[command_size];
    strncpy(command_copy, command, command_size - 1);
    command_copy[command_size - 1] = '\0';  // Ensure null termination
    
    // Execute the command
    printf("Executing command from code segment: %s\n", command_copy);
    system(command_copy);
}

void component_privileged_CWE78_bad() {
    CWE78_OS_Command_Injection__char_console_system_01_bad();
}
