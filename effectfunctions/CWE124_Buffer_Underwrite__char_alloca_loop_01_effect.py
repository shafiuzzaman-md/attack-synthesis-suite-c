from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE124_Buffer_Underwrite__char_alloca_loop_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    data: int,  # User-controlled index
    user_mode: UserMode
) -> MemoryState:
   
   # Memory constraints
    if memory_segment.segment_name not in memory.layout:
        return memory  # Prevent invalid memory access

    if required_permissions.r != 1 or required_permissions.w != 1:
        return memory  # Ensure read-write permissions

    # STASE Constraints: Inserted dynamically based on extracted preconditions
    
    # Get buffer base address dynamically
    buffer_base_address = memory.layout[memory_segment.segment_name]
    element_size_bytes = WORD_SIZE // 8  

    # Calculate the underwrite address
    target_address = buffer_base_address - (data * element_size_bytes)  # Buffer underwrite!

    # Simulate writing to the underflowed buffer location
    corruption_value = (ord('C')).to_bytes(1, byteorder="little", signed=False) * 100  # Mimic the loop copy
    memory = memory.memory_write(target_address, corruption_value, user_mode)

    # Return the updated memory state
    return memory

