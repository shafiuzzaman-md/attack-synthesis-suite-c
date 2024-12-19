from memory_setup import create_memory_state
from cwe562_effect import CWE562_ReturnOfStackVariableAddress, SegmentIdentifier as StackSegmentIdentifier
from cwe587_effect import CWE587_AssignmentOfFixedAddressToPointer, SegmentIdentifier as CodeSegmentIdentifier
from cwe121_effect import CWE121_StackBasedBufferOverflow
from memory_model import Permissions
from config import WORD_SIZE  # Import the shared word size


def execute_chain_vulnerability(mem):
    """
    Vulnerability Chain Summary:
    1. CWE562 - Leak Stack Address: Leak a sensitive stack address (leaked_stack_addr) via a stack variable read vulnerability.
    2. CWE587 - Assign Pointer to Code Segment: Update a pointer variable to point to the start of the code segment (updated_pointer_addr).
    3. CWE121 - Stack-Based Buffer Overflow: Exploit a stack buffer overflow using:
       - Padding to fill the buffer
       - Overwriting with leaked_stack_addr for redirection/control
       - Injecting the command address (updated_pointer_addr) to execute malicious code
    The chain demonstrates escalation from information leakage to arbitrary code execution.
    """
    # STEP 1: CWE 562 - Leak a stack address
    leaked_stack_addr = CWE562_ReturnOfStackVariableAddress(
        memory=mem,
        memory_segment=StackSegmentIdentifier("Stack Segment"),
        required_permissions= Permissions(r=1, w=0, e=0),
        stack_variable_address= mem.layout["STACK_START"] + 0x100  # Arbitrary stack variable address
    )
    print(f"Leaked stack address: {hex(leaked_stack_addr)}")

    # STEP 2: CWE 587 - Updates a pointer variable to point to a fixed address (start of the code segment)
    updated_pointer_addr = CWE587_AssignmentOfFixedAddressToPointer(
        memory=mem,
        memory_segment= CodeSegmentIdentifier("Code Segment"),
        required_permissions= Permissions(r=1, w=1, e=0),  
        pointer_variable_address= mem.layout["STACK_START"] + 0x200,  # Arbitrary stack address for pointer storage,
        fixed_address= mem.layout["CODE_START"]
    )
    print(f"Pointer updated to code segment address: {hex(updated_pointer_addr)}")

    # STEP 3: CWE 121 - Exploit buffer overflow to overwrite control data
    # Craft payload to target specific locations in the code segment
    buffer_size = 16
    control_data_offset = 8  # Offset to reach control data (symbolic)

    # Injected input command targeting the code segment
    injected_command_address = updated_pointer_addr  # Target inside the code segment
 
    # Payload construction:
    # - Padding to fill the buffer
    # - Overwrite with leaked_stack_addr (e.g., redirection or saving data)
    # - Overwrite with injected_command_address to execute the command
    input_data = (
        b"A" * buffer_size +  # Buffer overflow padding
        leaked_stack_addr.to_bytes(WORD_SIZE // 8, "little") +  # Redirected stack address
        injected_command_address.to_bytes(WORD_SIZE // 8, "little")  # Target command address in code segment
    )

    # Execute buffer overflow
    stack_var_addr = leaked_stack_addr
    updated_mem = CWE121_StackBasedBufferOverflow(
        memory=mem,
        memory_segment=StackSegmentIdentifier("Stack Segment"),
        required_permissions=  Permissions(r=1, w=1, e=0),
        stack_variable_address=stack_var_addr,
        control_data_offset=control_data_offset,
        input_data=input_data,
        buffer_size=buffer_size
    )
    print("Buffer overflow executed and control data overwritten using leaked addresses.")

    # Verify memory states or output results
    try:
        # Read back to confirm changes
        read_back = updated_mem.memory_read(stack_var_addr, len(input_data), privileged=False)
        print(f"Memory at buffer address after overflow: {read_back}")
    except Exception as e:
        print(f"Error reading memory: {e}")


if __name__ == "__main__":
    mem = create_memory_state(WORD_SIZE)
    execute_chain_vulnerability(mem)
