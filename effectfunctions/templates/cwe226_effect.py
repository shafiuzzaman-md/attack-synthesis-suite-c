from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE226_Sensitive_InformationUnclearedBeforeRelease_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int,
    data: bytes,
    user_mode: UserMode
) -> bytes:
  
    # Memory constraints:
    if memory_segment.segment_name not in memory.layout:
        return b''  # If segment is not present, return empty bytes

    if required_permissions.r != 1 or required_permissions.w != 1:
        return b''  # Missing required permissions

    if len(data) == 0:
        return b''  # No sensitive data to store or leak

    # Step 1: Write the sensitive password into memory (simulating storage on the stack)
    memory = memory.memory_write(stack_variable_address, data, user_mode)

    # Step 2: Simulate using the password (authentication operation)
    # We assume some function consumes the password, but it remains in memory

    # Step 3: Failure to clear sensitive data (this is the vulnerability)
    memory = memory.memory_retain(stack_variable_address, len(data))  # Prevents automatic clearing

    # Step 4: Read the leaked sensitive data
    exposed_data = memory.memory_read(stack_variable_address, len(data), user_mode)

    return exposed_data  # Return the sensitive data that should have been cleared
