from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE121_StackBasedBufferOverflow(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int,
    control_data_offset: int,
    input_data: bytes,
    buffer_size: int,
    user_mode: UserMode
) -> MemoryState:
    """
    Models CWE121_StackBasedBufferOverflow.

    Constraints:
    - memory_segment.segment_name = "Stack Segment"
    - STACK_START ≤ stack_variable_address < STACK_END 
    - required_permissions at least rw- (r=1, w=1)
    - (len(input_data) - buffer_size) ≥ control_data_offset
    - len(input_data) ≥ buffer_size

    If triggered, overwrites memory starting at stack_variable_address with input_data,
    potentially overwriting control data located at control_data_offset.
    """

    # Check segment constraint
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE121: Not in stack segment")

    # Check permissions
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE121: Required rw- permissions not met")

    # Check triggering conditions
    if len(input_data) < buffer_size:
        # Not large enough to overflow
        return memory

    # Check if overflow can reach control data
    if (len(input_data) - buffer_size) < control_data_offset:
        raise ValueError("CWE121: Overflow cannot reach control data")

    # Perform the overflow write
    control_data_address = stack_variable_address + buffer_size + control_data_offset
    if control_data_address < stack_variable_address + len(input_data):
         memory = memory.memory_write(stack_variable_address, input_data, user_mode)

    return memory
