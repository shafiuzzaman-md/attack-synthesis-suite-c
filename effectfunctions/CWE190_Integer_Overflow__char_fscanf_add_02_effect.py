from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE190_Integer_Overflow__char_fscanf_add_02_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    data: int,  # Mimics char input
    user_mode: UserMode
) -> MemoryState:

    # Memory constraints
    if memory_segment.segment_name not in memory.layout:
        return memory  # Prevent invalid memory accesses

    if required_permissions.r != 1 or required_permissions.w != 1:
        return memory # Ensure required permissions

    # STASE Constraints 
    if data < 127:
        return memory

    buffer_base_address = memory.layout[memory_segment.segment_name]
    data_bytes = data.to_bytes(1, byteorder="little", signed=False)
    memory = memory.memory_write(buffer_base_address, data_bytes, user_mode)

    return memory
