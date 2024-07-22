# attack-synthesis-suite-c
This project demonstrates the chaining of multiple vulnerabilities from the Juliet test suite.

## system context
Consider a software system that offers both regular user tasks and administrative operations. The system is designed with clear boundaries: regular users have limited access and cannot perform critical operations, while administrative tasks are protected and require higher privileges.
## attack surface
The attack surface for this motivating example consists of two primary components:
-User-Accessible Functions: Functions that handle user inputs and run in user mode with limited permissions. Examples include buffer management functions that process user inputs.
- Privileged Functions: Functions that run with elevated permissions and perform critical system operations. Examples include command execution functions that impact the system’s overall security.

## threat model
- The attacker can interact with user mode functions but cannot directly access privileged mode functions.
- The attacker can provide inputs to user-accessible functions and exploit vulnerabilities within these functions.
- The system contains multiple vulnerabilities that can be chained together to escalate privileges.

# Project Structure

- common.h: Header file declaring global variables and utility functions used across the project.

- common.c: Defines the global variables and utility function.

- privileged.c: Defines the privileged functions.

- user_accessible.c: Contains user-accessible functions.

- testcases/: Directory containing the Juliet test suite.

- example.c: Contains the main function to demonstrate the vulnerability chaining process. It calls various components to exploit the vulnerabilities.

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
