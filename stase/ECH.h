#ifndef ECH_H
#define ECH_H

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "klee/klee.h"

// Global definitions or configurations used across your project
#define BUFFER_SIZE 256  // Common buffer size for vulnerability checks
#define MAX_COMMAND_LENGTH 100  // Maximum length of command inputs

// Setup or initialize KLEE symbolic variables or other configurations
void initialize_environment();

#endif // ECH_H
