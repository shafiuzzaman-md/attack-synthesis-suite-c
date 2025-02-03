import sys
import os

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

from memorymodel.memory_setup import create_memory_state
from effectfunctions.cwe226_effect import CWE226_SensitiveInformationUnclearedBeforeRelease, SegmentIdentifier
from memorymodel.memory_model import Permissions, UserMode
from memorymodel.config import WORD_SIZE  # e.g. 32 or 64 bits

def test_cwe226_vulnerability():
    """
    Demonstrates CWE-226: Sensitive Information Uncleared Before Release.
    Writes sensitive data to a chosen address (stack in this example), calls memory_retain,
    and verifies the data remains accessible afterwards.
    """
    # 1. Create a memory state
    memory = create_memory_state(WORD_SIZE)

    # 2. Choose a stack address for our sensitive data
    stack_variable_address = memory.layout["STACK_START"] + 0x100  # Arbitrary offset

    # 3. Define the sensitive data
    sensitive_data = b"super_secret_password"

    # 4. Permissions needed to read/write in the stack segment
    required_permissions = Permissions(r=1, w=1)

    # 5. User mode
    user_mode = UserMode.USER

    print("=== CWE-226 Demo ===")
    print(f"Sensitive data to write: {sensitive_data}")
    print(f"Chosen stack address: {hex(stack_variable_address)}")

    # 6. Execute the CWE-226 effect function
    exposed_data = CWE226_SensitiveInformationUnclearedBeforeRelease(
        memory=memory,
        memory_segment=SegmentIdentifier("Stack Segment"),
        required_permissions=required_permissions,
        variable_address=stack_variable_address,
        sensitive_data=sensitive_data,
        user_mode=user_mode
    )

    print(f"[INFO] Exposed data returned by the effect function: {exposed_data}")

    # 7. Optionally, read back the memory again to confirm the data is still physically present
    try:
        recovered_data = memory.memory_read(stack_variable_address, len(sensitive_data), privileged=False)
        print(f"[RESULT] Data recovered from memory after 'release': {recovered_data}")
    except Exception as e:
        print(f"[ERROR] Could not read from memory: {e}")

    print("=== CWE-226 Demo Completed ===")

if __name__ == "__main__":
    test_cwe226_vulnerability()
