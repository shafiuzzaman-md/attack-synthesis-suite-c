from memorymodel.memory_model import MemoryState, Permissions
from memorymodel.config import WORD_SIZE  

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name


def CWE587_Assignment_of_Fixed_Address_to_Pointer__basic_02_bad(
    memory: MemoryState,
    required_permissions: Permissions,
    pointer_variable_address: int,
    fixed_address: int
) -> int:
  
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE587: Read-write permission required")

    memory = memory.memory_write(
        target_address=pointer_variable_address,
        data=fixed_address.to_bytes(WORD_SIZE, 'little'), 
        privileged=False
    )
    updated_pointer = int.from_bytes(
        memory.memory_read(pointer_variable_address, WORD_SIZE, privileged=False),
        'little'
    )
    return updated_pointer
