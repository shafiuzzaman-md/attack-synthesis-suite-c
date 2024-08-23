#include "common.h"
#define OMITGOOD
#include "testcases/CWE78_OS_Command_Injection/s02/CWE78_OS_Command_Injection__char_console_system_01.c"

// Write a command to the code segment in privileged mode
void write_command_privileged(const char *command) {
    char *command_buffer = (char*) allocateMemorySegment(COMMAND_BUFFER_SIZE, CODE_SEGMENT, 1, 1, 1); // Readable, Writable, Executable in privileged mode

    if (command_buffer == NULL) {
        printf("Error: Memory allocation failed in the code segment.\n");
        return;
    }

    // Write the provided command to the command buffer
    strncpy(command_buffer, command, COMMAND_BUFFER_SIZE - 1);
    command_buffer[COMMAND_BUFFER_SIZE - 1] = '\0'; // Ensure null termination

    printf("Privileged command buffer setup in code segment: %s\n", command_buffer);
}

void component_privileged_CWE78_bad() {
    CWE78_OS_Command_Injection__char_console_system_01_bad();
}
