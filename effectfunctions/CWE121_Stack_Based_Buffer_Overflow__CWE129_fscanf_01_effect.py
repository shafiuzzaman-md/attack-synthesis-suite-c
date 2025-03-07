from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int,
    control_data_offset: int,
    data: int,
    user_mode: UserMode
) -> MemoryState:

    # Memory constraints
    if memory_segment.segment_name != "Stack Segment":
        return memory

    if required_permissions.r != 1 or required_permissions.w != 1:
        return memory

    # STASE constraints
    if data < 10:
        return memory

    # STASE+Memory Model constraints
    if (data - 10) < control_data_offset:
        return memory
       
    # Perform the overflow write
    element_size_bytes = WORD_SIZE // 8 
    control_data_address = stack_variable_address + (10 * element_size_bytes) + (control_data_offset * element_size_bytes)
    if control_data_address < stack_variable_address + (data * element_size_bytes):
         data_bytes = data.to_bytes(element_size_bytes, byteorder="little", signed=True)
         memory = memory.memory_write(control_data_address, data_bytes, user_mode)

    return memory