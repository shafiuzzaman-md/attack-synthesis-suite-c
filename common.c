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

// Function to simulate use of allocated memory
void use_memory(void *ptr, size_t size, int value) {
    if (ptr != NULL) {
        memset(ptr, value, size);
        printf("Memory at %p filled with value %d\n", ptr, value);
    } else {
        printf("Invalid memory pointer\n");
    }
}

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