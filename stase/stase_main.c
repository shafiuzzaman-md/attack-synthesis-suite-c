#include "ECH.h"
#include "../common.c"
#include "../user_accessible.c"



void test_CWE121_CWE129_large() {

    int index;
    klee_make_symbolic(&index, sizeof(index), "index");
    u_CWE121_CWE129_large_01_bad(index);
}

void test_CWE121_CWE131_loop() {

    int source_size;  // Define the size of the source array
    klee_make_symbolic(&source_size, sizeof(int), "source_size");
    klee_assume(source_size > 0);
    int *source = (int *)malloc(source_size * sizeof(int));
    if (source == NULL) {
        printf("Error: Memory allocation failed.\n");
        exit(1);
    }

    klee_make_symbolic(source, source_size * sizeof(int), "source");
    u_CWE121_CWE131_loop_01_bad(source, source_size);
    free(source);
}

#define RUN_TEST_CWE121_CWE129 0
#define RUN_TEST_CWE121_CWE131 1

int main() {

    initialize_environment();

    if (RUN_TEST_CWE121_CWE129) {
        test_CWE121_CWE129_large();
    }
    if (RUN_TEST_CWE121_CWE131) {
        test_CWE121_CWE131_loop();
    }

    return 0;
}

// int main() {

//     initialize_environment();

//     //CWE121_CWE129
//     klee_make_symbolic(&BUFFER_SIZE, sizeof(BUFFER_SIZE), "BUFFER_SIZE");
//     int index;
//     klee_make_symbolic(&index, sizeof(index), "index");
//     u_CWE121_CWE129_large_01_bad(index);

//     // CWE121_CWE131
//     int size = 10;  // Define the size of the source array
//     int *source = (int *)malloc(size * sizeof(int));
//     if (source == NULL) {
//         printf("Error: Memory allocation failed.\n");
//         return;
//     }

//     // Make the source array symbolic
//     klee_make_symbolic(source, size * sizeof(int), "source");
//     // Call the modified function with the source array
//     u_CWE121_CWE131_loop_01_bad(source);
//     // Clean up
//     free(source);

//     // Make user_data and input_char symbolic values for KLEE to explore different paths
//     // char user_data;
//     // char input_char;
//     // klee_make_symbolic(&user_data, sizeof(user_data), "user_data");
//     // klee_make_symbolic(&input_char, sizeof(input_char), "input_char");
//     // u_CWE190_char_fscanf_add_01_bad(user_data, input_char);

//     // char command_buffer[100];
//     // char data[] = "safe_command"; // Example data, make symbolic for real testing
//     // klee_make_symbolic(data, sizeof(data), "data");

//     // CWE78_OS_Command_Injection__char_connect_socket_execl_01_bad(data, command_buffer);

//     // char user_data;
//     // char input_char = 'a'; // Example input character
//     // char user_buffer[BUFFER_SIZE];

//     // // Make user_data symbolic to explore different potential underflows
//     // klee_make_symbolic(&user_data, sizeof(user_data), "user_data");
    
//     // // Initialize buffer
//     // char *allocated_buffer = allocateMemorySegment(BUFFER_SIZE, 1, 1, 1, 0);
//     // if (allocated_buffer == NULL) {
//     //     printLine("Error: Memory allocation failed.");
//     //     return -1;
//     // }

//     // CWE191_Integer_Underflow__char_fscanf_multiply_01_bad(user_data, allocated_buffer, input_char);
    
//     // char source[15];
//     // size_t read_size = 20; // Intentionally larger than buffer size to simulate potential overread
//     // size_t buffer_size = sizeof(source);

//     // klee_make_symbolic(source, sizeof(source), "source");
//     // klee_make_symbolic(&read_size, sizeof(read_size), "read_size");
//     // klee_make_symbolic(&buffer_size, sizeof(buffer_size), "buffer_size");

//     // char *result = u_CWE126_char_alloca_memcpy_01_bad(source, read_size, buffer_size);
//     // if (result != NULL) {
//     //     printLine(result);
//     //     free(result); // Free the dynamically allocated buffer
//     // }

//      // Define buffer and set symbolic values
//     // char source[50]; // Allocate a buffer with known size
//     // size_t read_size = 50; // Read the full buffer size as input

//     // klee_make_symbolic(source, sizeof(source), "source");
//     // klee_make_symbolic(&read_size, sizeof(read_size), "read_size");

//     // char *result = CWE127_Buffer_Underread__char_alloca_cpy_01_bad(source, read_size);
//     // if (result != NULL) {
//     //     printLine(result);
//     //     free(result); // Free the dynamically allocated buffer
//     // }
//     return 0;
// }