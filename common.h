#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 10
#define CMD_BUFFER_SIZE 100

extern int buffer[BUFFER_SIZE];
extern char command_buffer[CMD_BUFFER_SIZE];

void initialize_system();

#endif // COMMON_H
