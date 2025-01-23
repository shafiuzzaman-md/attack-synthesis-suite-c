from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE226_SensitiveInformationUnclearedBeforeRelease(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int,
    sensitive_data: bytes,
    user_mode: UserMode
) -> MemoryState:
    """
    Models a vulnerable scenario for CWE-226: Sensitive Information Uncleared
  
    Steps:
    1. Write sensitive_data (e.g., password) to stack_variable_address.
    2. Use memory_stack_release to simulate going "out of scope" without clearing.
    3. Perform a read from the same memory region to show the data is still present
       even though logically "released."

    Constraints:
    - memory_segment.segment_name = "Stack Segment"
    - required_permissions at least rw- (r=1, w=1)
    - len(sensitive_data) > 0

    :param memory: The current state of the memory.
    :param memory_segment: Identifies which segment we're operating on (should be "Stack Segment").
    :param required_permissions: Permissions needed (must have both read and write).
    :param stack_variable_address: The address in the stack where the data is stored.
    :param sensitive_data: The sensitive information to be stored.
    :param user_mode: The privilege mode (User or Kernel) of the caller.
    :return: Updated MemoryState reflecting the write, release, and read.
    """

    # 1. Ensure this is the correct segment
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE226: Operation not on stack segment")

    # 2. Check for read/write permissions
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE226: Required rw- permissions not met")

    # 3. Write the sensitive data to the stack
    if len(sensitive_data) == 0:
        return memory  # No data => no vulnerability triggered

    # Write password (or other sensitive info) to the stack
    memory = memory.memory_write(stack_variable_address, sensitive_data, user_mode)

    # 4. Simulate "releasing" this stack region WITHOUT clearing it
    #    (In a real function, the local buffer goes out of scope, but remains in memory.)
    memory = memory.memory_stack_release(stack_variable_address, len(sensitive_data))

    # 5. Demonstrate the data remains physically in memory by reading from the same area
    exposed_data = memory.memory_read(stack_variable_address, len(sensitive_data), user_mode)

    # Optional: For debugging or logging, one might print or record the exposed data:
    # print(f"[VULNERABILITY] Sensitive data still in memory (released): {exposed_data}")

    return memory
