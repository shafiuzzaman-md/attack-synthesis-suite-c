from memorymodel.memory_model import MemoryState, Permissions

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE562_Return_of_Stack_Variable_Address__return_pointer_buf_01_bad(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions
) -> int:
  
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE562: Not in 'Stack Segment'")

    if required_permissions.r != 1:
        raise PermissionError("CWE562: Read permission required")

    leaked_address = memory.get_stack_top()

    return leaked_address
