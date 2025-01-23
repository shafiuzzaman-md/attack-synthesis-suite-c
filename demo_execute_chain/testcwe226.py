import sys
import os

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)



from memorymodel.memory_setup import create_memory_state
from effectfunctions.cwe226_effect import CWE226_SensitiveInformationUnclearedBeforeRelease, SegmentIdentifier as StackSegmentIdentifier
from memorymodel.memory_model import Permissions, UserMode
from memorymodel.config import WORD_SIZE  # Import the shared word size

def test_cwe226_vulnerability():
    """
    Demonstrates CWE-226: Sensitive Information Uncleared Before Release.
    Writes sensitive data to a stack address, releases the stack without clearing it,
    and reads back to confirm the data remains accessible.
    """
    # Create the memory state
    memory = create_memory_state(WORD_SIZE)

    # Define stack address to use for the sensitive data
    stack_variable_address = memory.layout["STACK_START"] + 0x100  # Arbitrary stack address in stack segment

    # Sensitive data to write
    sensitive_data = b"super_secret_password"

    # Permissions required for stack access
    required_permissions = Permissions(r=1, w=1)

    # User mode
    user_mode = UserMode.USER

    # Print initial state
    print("=== CWE-226 Demo ===")
    print(f"Sensitive data to write: {sensitive_data}")
    print(f"Stack address: {hex(stack_variable_address)}")

    # Execute CWE-226 vulnerability function
    memory = CWE226_SensitiveInformationUnclearedBeforeRelease(
        memory=memory,
        memory_segment=StackSegmentIdentifier("Stack Segment"),
        required_permissions=required_permissions,
        stack_variable_address=stack_variable_address,
        sensitive_data=sensitive_data,
        user_mode=user_mode
    )

    # Attempt to read back the "released" stack memory
    try:
        recovered_data = memory.memory_read(stack_variable_address, len(sensitive_data), privileged=False)
        print(f"[RESULT] Data recovered from memory after release: {recovered_data}")
    except Exception as e:
        print(f"[ERROR] Could not read from memory: {e}")

    print("=== CWE-226 Demo Completed ===")


if __name__ == "__main__":
    test_cwe226_vulnerability()
