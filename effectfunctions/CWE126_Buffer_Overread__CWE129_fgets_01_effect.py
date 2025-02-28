from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE126_Buffer_Overread__CWE129_fgets_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    data: int,
    user_mode: UserMode
) -> int:
  
    # Memory constraints
    if memory_segment.segment_name not in memory.layout:
        return 0 

    if required_permissions.r != 1:
        return 0
    
    # STASE Constraint:
    if data < 10:
        return memory
    
    # Get buffer base address dynamically
    buffer_base_address = memory.layout[memory_segment.segment_name]
    element_size_bytes = WORD_SIZE // 8  
    target_address = buffer_base_address + (data * element_size_bytes)  # Overread happens here!

    # Perform the buffer overread
    memory_data = memory.memory_read(target_address, element_size_bytes, user_mode)

    return int.from_bytes(memory_data, byteorder="little", signed=True)  # Returns overread value
