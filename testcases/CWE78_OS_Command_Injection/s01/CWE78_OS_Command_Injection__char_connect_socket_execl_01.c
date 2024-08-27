/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_connect_socket_execl_01.c
Label Definition File: CWE78_OS_Command_Injection.strings.label.xml
Template File: sources-sink-01.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Fixed string
 * Sink: execl
 *    BadSink : execute command with execl
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define COMMAND_INT_PATH "%WINDIR%\\system32\\cmd.exe"
#define COMMAND_INT "cmd.exe"
#define COMMAND_ARG1 "/c"
#define COMMAND_ARG2 "dir "
#define COMMAND_ARG3 data
#else /* NOT _WIN32 */
#include <unistd.h>
#define COMMAND_INT_PATH "/bin/sh"
#define COMMAND_INT "sh"
#define COMMAND_ARG1 "-c"
#define COMMAND_ARG2 "ls "
#define COMMAND_ARG3 data
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else /* NOT _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"

#ifdef _WIN32
#include <process.h>
#define EXECL _execl
#else /* NOT _WIN32 */
#define EXECL execl
#endif

#ifndef OMITBAD

void CWE78_OS_Command_Injection__char_connect_socket_execl_01_bad(char * data, char *command_buffer)
{
    #ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
    #endif
    int recvResult;
    struct sockaddr_in service;
    char *replace;
    SOCKET connectSocket = INVALID_SOCKET;
    size_t dataLen = 0;  // Initially, the length is 0

    do
    {
    #ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        {
            break;
        }
        wsaDataInit = 1;
    #endif
        /* POTENTIAL FLAW: Read data using a connect socket */
        connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connectSocket == INVALID_SOCKET)
        {
            break;
        }
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
        service.sin_port = htons(TCP_PORT);
        if (connect(connectSocket, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
        {
            break;
        }
        /* Abort on error or the connection was closed */
        recvResult = recv(connectSocket, (char *)(command_buffer + dataLen), sizeof(char) * (100 - dataLen - 1), 0);
        if (recvResult == SOCKET_ERROR || recvResult == 0)
        {
            break;
        }
        /* Append null terminator */
        command_buffer[dataLen + recvResult / sizeof(char)] = '\0';
        /* Eliminate CRLF */
        replace = strchr(command_buffer, '\r');
        if (replace)
        {
            *replace = '\0';
        }
        replace = strchr(command_buffer, '\n');
        if (replace)
        {
            *replace = '\0';
        }
    } while (0);

    if (connectSocket != INVALID_SOCKET)
    {
        CLOSE_SOCKET(connectSocket);
    }
    #ifdef _WIN32
    if (wsaDataInit)
    {
        WSACleanup();
    }
    #endif

    /* Validate the command in the code segment to prevent command injection */
    //klee_make_symbolic(command_buffer, sizeof(char) * 100, "command_buffer");

    // Predicate function to ensure no command injection occurs
    int valid_command_input = 1;
    for (size_t i = 0; i < strlen(command_buffer); i++)
    {
        if (command_buffer[i] == '&' || command_buffer[i] == ';' || command_buffer[i] == '|' || command_buffer[i] == '$' || command_buffer[i] == '`' || command_buffer[i] == '<' || command_buffer[i] == '>')
        {
            valid_command_input = 0;
            break;
        }
    }
    //klee_assert(valid_command_input);

    /* Execute the command stored in the code segment */
    printf("Executing command: %s\n", command_buffer);
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, command_buffer, COMMAND_ARG3, NULL);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100] = COMMAND_ARG2;
    data = dataBuffer;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");
    /* execl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL);
}

void CWE78_OS_Command_Injection__char_connect_socket_execl_01_good()
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
    CWE78_OS_Command_Injection__char_connect_socket_execl_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE78_OS_Command_Injection__char_connect_socket_execl_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
