from memorymodel.memory_model import MemoryState, Permissions

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE194_Unexpected_Sign_Extension(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    data: int
) -> MemoryState:
   
    if memory_segment.segment_name not in memory.layout:
        return memory 

    if required_permissions.r != 1 or required_permissions.w != 1:
        return memory  

    # Vulnerable operation: sign extension during heap allocation
    alloc_size = data
    memory = memory.heap_alloc(alloc_size)

    # Return updated memory state
    return memory
