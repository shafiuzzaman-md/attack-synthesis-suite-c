from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_01_bad(
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

    # No STASE constraints because preconditions are null

    # STASE+Memory Model constraints
    if data < (stack_variable_address + control_data_offset):
        return memory

    control_data_address = stack_variable_address + control_data_offset

     # Perform the overflow write
    control_data_address = stack_variable_address + control_data_offset
    if control_data_address < stack_variable_address + len(data):
         memory = memory.memory_write(stack_variable_address, data, user_mode)

    return memory