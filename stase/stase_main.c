#include "ECH.c"
#include "../common.c"
#include "../user_accessible.c"

//Symbolic buffer_size for buffer overflow detection
int symbolic_BUFFER_SIZE; 

// Predicate function to check for buffer overflow
int no_buffer_overflow_occurred(int index, int buffer_size) {
    return (index >= 0 && index < buffer_size);
}


int main() {
    // Make user_data a symbolic value for KLEE to explore different paths
    int user_data;
    klee_make_symbolic(&user_data, sizeof(user_data), "user_data");
    u_CWE121_CWE129_large_01_bad(user_data);

    return 0;
}