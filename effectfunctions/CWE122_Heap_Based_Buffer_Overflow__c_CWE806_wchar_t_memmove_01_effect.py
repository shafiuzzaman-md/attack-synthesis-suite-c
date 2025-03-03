
from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memmove_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    heap_alloc_address: int,
    control_data_offset: int,  # Tracks corruption beyond buffer
    data: bytes,
    user_mode: UserMode
) -> MemoryState:
  
    if memory_segment.segment_name != "Heap Segment":
        raise ValueError("CWE122: Operation not on the heap segment")
    
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE122: Required read-write permissions not met")

    memcpy_size = control_data_offset 

    memory = memory.memory_write(heap_alloc_address, data[:memcpy_size], user_mode)

    return memory
