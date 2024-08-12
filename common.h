#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

// Function prototypes for the components
void component_input_CWE121_bad(int user_data, char *user_buffer);
char* component_input_CWE78_bad(char *user_data);
void component_privileged_CWE78_bad();

// Additional functions for system initialization
void initialize_system();

#endif // COMMON_H
