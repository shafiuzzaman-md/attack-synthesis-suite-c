#include "common.h"

// Include the Juliet test suite file
#define OMITGOOD
#define BUFFER_SIZE 256

#include "testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.c"


// Simulate command execution (accessible in user mode)
void execute_command(int command_number) {
    char *command_start = command_buffer;
    char *command_end;
    int current_command = 0;

    // Iterate through the commands in the buffer
    while ((command_end = strchr(command_start, ';')) != NULL || *command_start != '\0') {
        if (current_command == command_number) {
            // Null-terminate the specific command
            if (command_end != NULL) {
                *command_end = '\0';
            }

            // Execute the specific command
            printf("Executing command from code segment: %s\n", command_start);
            system(command_start);
            return;
        }
        current_command++;

        if (command_end == NULL) {
            break;
        }

        // Move to the next command
        command_start = command_end + 1;
    }

    printf("ERROR: Command number %d not found in command buffer.\n", command_number);
}


// Simulate buffer overflow vulnerability with large index access
void u_CWE121_CWE129_large_01_bad(int user_data, char *user_buffer) {
    CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01_bad(user_data, user_buffer);
}

// Simulate buffer overflow vulnerability with negative index access
// void u_CWE121_CWE129_negative_01_bad(int user_data, char *user_buffer) {
//     CWE121_Stack_Based_Buffer_Overflow__CWE129_negative_01_bad(user_data, user_buffer);
// }

// Simulate a use-after-free vulnerability with direct user input
// char* u_CWE416_malloc_free_01_bad(int user_data, char *user_buffer) {
//     CWE416_Use_After_Free__malloc_free_char_01_bad(user_data, user_buffer);
//     return user_buffer;  // Return the potentially dangling pointer after use-after-free
// }


