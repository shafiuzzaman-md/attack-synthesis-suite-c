#include "ECH.c"
#include "../common.c"
#include "../user_accessible.c"

//Symbolic buffer_size for buffer overflow detection
int symbolic_BUFFER_SIZE; 
// Predicate function that asserts no buffer overflow has occurred
int no_buffer_overflow_occurred(int data, int buffer_size) {
    return data >= 0 && data < buffer_size;
}

int main()
{
  //Symbolic buffer size
  klee_make_symbolic(&symbolic_BUFFER_SIZE, sizeof(symbolic_BUFFER_SIZE), "buffer_size");

  int user_data;
  user_data = klee_int("user_data");
  klee_make_symbolic(&current_mode, sizeof(current_mode), "current_mode");

  u_CWE121_CWE129_large_01_bad(user_data);
  execute_command_user(user_data);
}