/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_console_system_01.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-01.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sink: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 01 Baseline
 *
 * */



#include "../../../testcasesupport/std_testcase.h"
#include "../../../common.h"
#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND "dir "
#else
#include <unistd.h>
#define FULL_COMMAND "ls "
#endif

#ifdef _WIN32
#define SYSTEM system
#else /* NOT _WIN32 */
#define SYSTEM system
#endif

#ifndef OMITBAD
#define COMMAND_BUFFER_SIZE 128  // Define the command buffer size as 128 bytes
void CWE78_OS_Command_Injection__char_console_system_01_bad() {
    // Allocate memory for the command to be executed
    char command[COMMAND_BUFFER_SIZE] = "cmd /c ";

    // Allocate the command_buffer as a protected memory segment
    char *command_buffer = (char*) allocateMemorySegment(COMMAND_BUFFER_SIZE, PROTECTED_SEGMENT, 1, 0, 0); // Readable, Non-Writable, Non-Executable

    if (command_buffer == NULL) {
        printf("ERROR: Memory allocation for command buffer failed.\n");
        return;
    }

    // Simulate populating the command buffer with data (for demonstration purposes only)
    strncpy(command_buffer, "echo Hello, World!", COMMAND_BUFFER_SIZE - 1);
    command_buffer[COMMAND_BUFFER_SIZE - 1] = '\0';  // Ensure null termination

    // Check if the command buffer content is within bounds and can be appended to the command
    if (strlen(command_buffer) < (COMMAND_BUFFER_SIZE - strlen(command))) {
        // Attempt to append the protected command buffer to the command string
        strcat(command, command_buffer);
        printf("Executing command: %s\n", command);

        // Execute the command
        system(command);
    } else {
        printf("ERROR: Command buffer overflow.\n");
    }

    // Free the allocated protected memory segment
    freeMemorySegment(command_buffer);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) != 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

void CWE78_OS_Command_Injection__char_console_system_01_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE78_OS_Command_Injection__char_console_system_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE78_OS_Command_Injection__char_console_system_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
