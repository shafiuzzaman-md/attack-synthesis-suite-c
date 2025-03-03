#include <stdio.h>
#include "klee/klee.h"
#include "../instrumented_code/CWE194_Unexpected_Sign_Extension__fgets_malloc_01.c"

int main() {
    CWE194_Unexpected_Sign_Extension__fgets_malloc_01_bad();
    CWE194_Unexpected_Sign_Extension__fgets_malloc_01_good();
    return 0;
}
