from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int,
    control_data_offset: int, 
    data: int,
    user_mode: UserMode
) -> MemoryState:
    """
    Instantiated effect function for CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.c
    """

    # Memory constraints
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE121: Not in stack segment")

    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE121: Required rw- permissions not met")

    # STASE constraints
    if data < 10:
        return memory

    # STASE+Memory Model constraints
    if (data - 10) < control_data_offset:
        raise ValueError("CWE121: Overflow cannot reach control data")

    control_data_address = stack_variable_address + 10 + control_data_offset

    if control_data_address < (stack_variable_address + data):
        element_size = WORD_SIZE // 8  
        value_bytes = (1).to_bytes(element_size, byteorder='little', signed=True)
        memory = memory.memory_write(stack_variable_address, value_bytes, user_mode)

    return memory
