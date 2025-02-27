from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE126_Buffer_Overread__CWE129_large_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    data: int,
    user_mode: UserMode
) -> MemoryState:
  
     # Memory constraints
    if memory_segment.segment_name not in ["Heap Segment", "Stack Segment"]:
        return memory

    if required_permissions.r != 1:
        return memory

    element_size_bytes = WORD_SIZE // 8  
    target_address = data * element_size_bytes 

    data_bytes = memory.memory_read(target_address, element_size_bytes, user_mode)

    return int.from_bytes(data_bytes, byteorder="little")
