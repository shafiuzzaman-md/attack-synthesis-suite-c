#include "common.h"

// Include the Juliet test suite file
#define OMITGOOD
#define BUFFER_SIZE 10
int EXECUTE = 1;
#include "testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.c"
#include "testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_fscanf_add_01.c"
#include "testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_01.c"

// Execute a specific command stored in the code segment
void u_execute_command(int command_number) {
     if (current_mode != USER_MODE) {
        printf("ERROR: Attempt to execute user command in non-user mode.\n");
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
    klee_assert(!EXECUTE);
    // Null-terminate the selected command for execution
    char command_copy[command_size];
    strncpy(command_copy, command, command_size - 1);
    command_copy[command_size - 1] = '\0';  // Ensure null termination
    
    // Execute the command
    printf("Executing command from code segment: %s\n", command_copy);
    system(command_copy);
}

void u_CWE121_CWE129_large_01_bad(int user_data) {
     if (current_mode != USER_MODE) {
        printf("ERROR: Attempt to execute user command in non-user mode.\n");
        return;
    }
    // Allocate a buffer in the data segment
    char *user_buffer = (char*) allocateMemorySegment(BUFFER_SIZE, DATA_SEGMENT, 1, 1, 0); // Readable, Writable
    if (user_buffer == NULL) {
        printf("Error: Memory allocation failed in the data segment.\n");
        return;
    }
    CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01_bad(user_data, user_buffer);
}


void u_CWE190_char_fscanf_add_01_bad(char user_data, char input_char) {
     if (current_mode != USER_MODE) {
        printf("ERROR: Attempt to execute user command in non-user mode.\n");
        return;
    }
    // Allocate a buffer in the data segment
    char *user_buffer = (char*) allocateMemorySegment(BUFFER_SIZE, DATA_SEGMENT, 1, 1, 0); // Readable, Writable
    if (user_buffer == NULL) {
        printf("Error: Memory allocation failed in the data segment.\n");
        return;
    }
    CWE190_Integer_Overflow__char_fscanf_add_01_bad(user_data, *user_buffer,  input_char);
}

void u_CWE78_OS_char_connect_socket_execl_01_bad(char user_data) {
     if (current_mode != USER_MODE) {
        printf("ERROR: Attempt to execute user command in non-user mode.\n");
        return;
    }

    // Allocate a buffer in the code segment for storing the command
    char *command_buffer = (char*) allocateMemorySegment(100, CODE_SEGMENT, 1, 0, 1);

    if (command_buffer == NULL) {
        printf("Error: Memory allocation failed in the data segment.\n");
        return;
    }
    CWE78_OS_Command_Injection__char_connect_socket_execl_01_bad(user_data, *command_buffer);
}


void u_CWE191_char_fscanf_multiply_01_bad(char user_data, char input_char) {
     if (current_mode != USER_MODE) {
        printf("ERROR: Attempt to execute user command in non-user mode.\n");
        return;
    }
    // Allocate a buffer in the data segment
    char *user_buffer = (char*) allocateMemorySegment(BUFFER_SIZE, DATA_SEGMENT, 1, 1, 0); // Readable, Writable
    if (user_buffer == NULL) {
        printf("Error: Memory allocation failed in the data segment.\n");
        return;
    }
    CWE191_Integer_Underflow__char_fscanf_multiply_01_bad(user_data, *user_buffer,  input_char);
}




// Simulate a use-after-free vulnerability with direct user input
// char* u_CWE416_malloc_free_01_bad(int user_data, char *user_buffer) {
//     CWE416_Use_After_Free__malloc_free_char_01_bad(user_data, user_buffer);
//     return user_buffer;  // Return the potentially dangling pointer after use-after-free
// }


