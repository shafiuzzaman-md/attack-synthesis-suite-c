#include "common.h"

// Define memory segment structure
typedef struct {
    void* baseAddress;
    size_t size;
    MemoryType type;
    uint8_t read;
    uint8_t write;
    uint8_t execute;
} MemorySegment;

// Global pointers to buffers
char *user_buffer;
char *command_buffer;
char *reserved_buffer;
char *protected_buffer;  // Added for protected segment

// Define memory map structure
#define MAX_MEMORY_SEGMENTS 10
MemorySegment memoryMap[MAX_MEMORY_SEGMENTS];
int memorySegmentCount = 0;

// Function to allocate a memory segment
void* allocateMemorySegment(size_t size, MemoryType type, uint8_t read, uint8_t write, uint8_t execute) {
    if (memorySegmentCount >= MAX_MEMORY_SEGMENTS) {
        printf("Error: Maximum memory segments reached.\n");
        return NULL;
    }

    void* baseAddress = malloc(size);
    if (baseAddress == NULL) {
        printf("Error: Memory allocation failed.\n");
        return NULL;
    }

    MemorySegment segment = {
        .baseAddress = baseAddress,
        .size = size,
        .type = type,
        .read = read,
        .write = write,
        .execute = execute
    };

    memoryMap[memorySegmentCount++] = segment;
    printf("Allocated memory segment of type %d, size %zu bytes at %p.\n", type, size, baseAddress);
    return baseAddress;
}

// Allocate memory for user, command, reserved, and protected buffers
// void allocate_all_buffers() {
//     user_buffer = (char*) allocateMemorySegment(BUFFER_SIZE, DATA_SEGMENT, 1, 1, 0); // Readable, Writable
//     command_buffer = (char*) allocateMemorySegment(COMMAND_BUFFER_SIZE, CODE_SEGMENT, 1, 0, 1); // Readable, Executable, Non-Writable in User Mode
//     reserved_buffer = (char*) allocateMemorySegment(RESERVED_BUFFER_SIZE, RESERVED_SEGMENT, 1, 0, 0); // Readable, Non-Writable
//     protected_buffer = (char*) allocateMemorySegment(PROTECTED_BUFFER_SIZE, PROTECTED_SEGMENT, 1, 1, 0); // Readable, Writable

//     if (user_buffer == NULL || command_buffer == NULL || reserved_buffer == NULL || protected_buffer == NULL) {
//         printf("Error: Memory allocation failed.\n");
//         exit(1);
//     }
// }

// Function to free a memory segment
void freeMemorySegment(void* baseAddress) {
    for (int i = 0; i < memorySegmentCount; i++) {
        if (memoryMap[i].baseAddress == baseAddress) {
            free(baseAddress);
            printf("Freed memory segment of type %d at %p.\n", memoryMap[i].type, baseAddress);

            // Shift remaining segments
            for (int j = i; j < memorySegmentCount - 1; j++) {
                memoryMap[j] = memoryMap[j + 1];
            }
            memorySegmentCount--;
            return;
        }
    }
    printf("Error: Memory segment not found.\n");
}

// Free all allocated buffers
// void free_all_buffers() {
//     freeMemorySegment(user_buffer);
//     freeMemorySegment(command_buffer);
//     freeMemorySegment(reserved_buffer);
//     freeMemorySegment(protected_buffer);  // Free protected buffer
// }

// Dummy system initialization function
void initialize_system() {
    printf("System initialized.\n");
}

// Define printLine to print a string followed by a newline
void printLine(const char *line) {
    printf("%s\n", line);
}

// Define printIntLine to print an integer followed by a newline
void printIntLine(int value) {
    printf("%d\n", value);
}
