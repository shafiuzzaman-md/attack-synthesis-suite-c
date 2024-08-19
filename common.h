#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Buffer sizes
#define BUFFER_SIZE 256
#define COMMAND_BUFFER_SIZE 128
#define RESERVED_BUFFER_SIZE 64
#define PROTECTED_BUFFER_SIZE 64  // Added for protected segment

// Define generalized memory segment types
typedef enum {
    CODE_SEGMENT,
    DATA_SEGMENT,
    RESERVED_SEGMENT,
    PROTECTED_SEGMENT
} MemoryType;

// Memory management functions
void* allocateMemorySegment(size_t size, MemoryType type, uint8_t read, uint8_t write, uint8_t execute);
void freeMemorySegment(void* baseAddress);
void allocate_all_buffers();
void free_all_buffers();

// Global buffers (declare them as extern so they are accessible across files)
extern char *user_buffer;
extern char *command_buffer;
extern char *reserved_buffer;
extern char *protected_buffer;  // Added for protected segment

// System initialization
void initialize_system();

// Printing functions
void printLine(const char *line);
void printIntLine(int value);

// Declare the functions used across multiple source files
void execute_command(int command_number);
void u_CWE121_CWE129_large_01_bad(int user_data, char *user_buffer);  // Declare the function here

#endif // COMMON_H
