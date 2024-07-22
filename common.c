#include "common.h"

int buffer[BUFFER_SIZE];
char command_buffer[CMD_BUFFER_SIZE];

void initialize_system() {
    memset(buffer, 0, sizeof(buffer));
    memset(command_buffer, 0, sizeof(command_buffer));
    printf("System initialized.\n");
}

void printIntLine(int intNumber) {
    printf("%d\n", intNumber);
}

void printLine(const char * line) {
    printf("%s\n", line);
}