# Attack Synthesis Suite C
This project demonstrates the chaining of multiple vulnerabilities from the Juliet test suite, focusing on how user-accessible vulnerabilities can be exploited and combined to escalate privileges within a software system. The system is modeled to reflect real-world scenarios, motivated by the architecture and security concerns of kernel development, UEFI firmware, and Android device drivers, where memory segments are strictly controlled to maintain security.

## System Context
Consider a software system that supports both regular user tasks and administrative operations. The system is architected with distinct memory segments to enforce security boundaries:

Regular users are confined to User Mode, where they can perform standard operations with access restricted to non-critical memory areas, specifically the Data Segment and Code Segment.
Administrative tasks are executed in Privileged Mode, where they have full access to Protected Segments and Reserved Segments, allowing them to perform critical system operations that require elevated permissions.

## Memory Model

| **Segment Type**        | **Purpose**                         | **User Mode**                | **Privileged Mode**            | **Example (UEFI/Kernel/Android)**                    |
|-------------------------|-------------------------------------|------------------------------|--------------------------------|------------------------------------------------------|
| **Reserved Segment**    | System-critical functions           | No access                    | Read-only                      | Interrupt vector table, MMIO regions, BIOS settings  |
| **Protected Segment**   | Sensitive data and configurations   | No access                    | Full access (read/write)       | UEFI variables, kernel security keys, Android keystore |
| **Code Segment**        | Executable program instructions     | Read and execute             | Full access (read/write/execute) | UEFI boot code, kernel code, Android system libraries |
| **Data Segment**        | Program data (variables, buffers)   | Read and write               | Full access (read/write)       | Global variables, heap, stack memory                 |


## Attack Surface
The attack surface for this system is divided into two main components:

### User-Accessible Functions:

These functions operate in User Mode with access limited to the Data Segment for reading and writing and the Code Segment for executing instructions. They handle user inputs and perform regular tasks such as buffer management.
Examples: Buffer management functions that process and store user inputs in the Data Segment and executable code that resides in the Code Segment.
Privileged Functions:

These functions run in Privileged Mode with full access to all memory segments, including Protected Segments and Reserved Segments. They are responsible for executing critical system operations that affect overall system security.
Examples: Functions that manage security keys stored in the Protected Segment, execute system-level commands, or interact with hardware via Reserved Segments.

## threat model
- The attacker can interact with user mode functions but cannot directly access privileged mode functions.
- The attacker can provide inputs to user-accessible functions and exploit vulnerabilities within these functions.
- The system contains multiple vulnerabilities that can be chained together to escalate privileges.

# Project Structure

- common.h: Defines the foundational structures and functions for a memory model that differentiates between various types of memory segments. 

- common.c: Defines the global variables and utility function.

- privileged.c: Defines the privileged functions.

- user_accessible.c: Contains user-accessible functions.

- testcases/: Directory containing the Juliet test suite.

- example.c: Contains the main function to demonstrate an example of the vulnerability chaining process. 

# Memory Segment Types (MemoryType)

- Data Segment (DATA_SEGMENT):
    - Purpose: Stores global variables, heap data, and other mutable data that a program might need to read from or write to.
    - Access Control:
        - User Mode: Readable and writable, but not executable. 
        - Privileged Mode: Readable, writable, and may have additional privileges for certain operations (e.g., direct memory access).

- Code Segment (CODE_SEGMENT):
    - Purpose: Stores the executable instructions of the program.
    - Access Control:
        - User Mode: Readable and executable, but not writable. 
        - Privileged Mode: Readable, executable, and in some cases writable (e.g., for just-in-time compilation or certain debugging operations). Privileged code might need to modify executable code under specific, controlled circumstances.

- Protected Segment (PROTECTED_SEGMENT):
    - Purpose: Contains sensitive data or commands. 
    - Access Control:
        - User Mode: No access. 
        - Privileged Mode: Readable, and in some cases writable, depending on the specific use case. Only privileged code can access this segment, typically for executing sensitive operations or modifying protected settings.

- Reserved Segment (RESERVED_SEGMENT):
    - Purpose: Reserved for critical system functions or hardware interactions.
    - Access Control:
        - User Mode: No access. 
        - Privileged Mode: Restricted and controlled access.
            - Read: Restricted; only specific low-level operations can read this segment
            - Write: Restricted; only specific system functions or hardware interactions may write to this segment.
            - Execute: Typically not allowed; reserved segments generally do not contain executable code. In very specialized cases, certain low-level operations might execute here.
         

## Memory Segment Access Control Summary

| **Segment Type**        | **User Mode Read** | **User Mode Write** | **User Mode Execute** | **Privileged Mode Read** | **Privileged Mode Write** | **Privileged Mode Execute** |
|-------------------------|--------------------|---------------------|-----------------------|--------------------------|---------------------------|-----------------------------|
| **Reserved Segment**     | No                 | No                  | No                    | Restricted                | Restricted                 | Typically No                |
| **Protected Segment**    | No                 | No                  | No                    | Yes                       | Yes (controlled)           | No                          |
| **Code Segment**         | Yes                | No                  | Yes                   | Yes                       | Yes (specific conditions)  | Yes                         |
| **Data Segment**         | Yes                | Yes                 | No                    | Yes                       | Yes                        | No                          |

### Key Points:
- **Reserved Segment**: Highly restricted, used for critical system functions with very limited access, even in privileged mode.
- **Protected Segment**: No access in user mode; controlled read and write access in privileged mode, typically for sensitive data.
- **Code Segment**: Readable and executable in both modes, but writable only in privileged mode under specific conditions to maintain the integrity of executable code.
- **Data Segment**: Fully accessible for reading and writing in both modes, but not executable to prevent running arbitrary data as code.

# Compiling and Running

`cd attack-synthesis-suite-c`

`clang -o exploit example.c common.c privileged.c user_accessible.c`

`./exploit`



# Juliet Test Suite for C/C++

This is the Juliet Test Suite for C/C++ version 1.3 from https://samate.nist.gov/SARD/testsuite.php augmented with a build system for Unix-like OSes that supports automatically building test cases into individual executables and running those tests. The build system originally provided with the test suite supports building all test cases for a particular [CWE](https://cwe.mitre.org/) into a monolithic executable. Building individual test cases supports the evaluation of projects like [CHERI](https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/) that facilitate memory safety for C/C++ programs at runtime. 

Testcases are organized by CWE in the `testcases` subdirectory. `juliet.py` is the main script that supports building and running individual test cases - individual CWEs or the entire test suite can be targeted. To build executables, `juliet.py` copies `CMakeLists.txt` into the directories for targeted CWEs and runs cmake followed by make. Output appears by default in a `bin` subdirectory. Each targeted CWE has a `bin/CWEXXX` directory that is further divided into `bin/CWEXXX/good` and `bin/CWEXXX/bad` subdirectories. For each test case, a "good" binary that does not contain the error is built and placed into the good subdirectory and a "bad" binary that contains the error is built and placed into the bad subdirectory.

To run executables after they are built, `juliet.py` invokes the `juliet-run.sh` script, which is copied to the `bin` subdirectory during the build. It records exit codes in `bin/CWEXXX/good.run` and `bin/CWEXXX/bad.run`. Executables are run with a timeout so that test cases depending on user input timeout with exit code 124.

**Note:** Juliet C++ test cases that use namespace std and the bind() socket function didn't compile under c++11, which introduces std::bind(). This version of the test suite has replaced `bind()` calls in C++ source files with calls to `::bind()`.

## Running tests on CheriBSD

TODO

To run the tests on CHERI you can use [cheribuild](https://github.com/CTSRD-CHERI/cheribuild):
`cheribuild.py juliet-c-cheri --build-and-test` will build and run the tests (assuming you have built the SDK and a CheriBSD image first).

You can also manually mount the built `bin` subdirectory on a CheriBSD host and use the `juliet-run.sh` script directly to run tests.
