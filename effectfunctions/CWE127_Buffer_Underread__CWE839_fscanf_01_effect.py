from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE127_Buffer_Underread__CWE839_fscanf_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    data: int,
    user_mode: UserMode
) -> int:
  
     # Memory constraints
    if required_permissions.r != 1:
        return 0

    buffer_base_address = memory.layout[memory_segment.segment_name] 
   
     # STASE constraints
    if data >= 0:
        return 0
    
    element_size_bytes = WORD_SIZE // 8  
    target_address = buffer_base_address + (data * element_size_bytes)

    memory_data = memory.memory_read(target_address, element_size_bytes, user_mode)

    return int.from_bytes(memory_data, byteorder="little", signed=True)

