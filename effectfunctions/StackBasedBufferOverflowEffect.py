from memory_model import MemoryState, Permissions
from memory_setup import create_memory_state

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
    buffer_size: int
) -> MemoryState:
    """
    Models CWE121_StackBasedBufferOverflow.

    Constraints:
    - memory_segment.segment_name = "Stack Segment"
    - STACK_START ≤ stack_variable_address < STACK_END 
    - required_permissions at least rw- (r=1, w=1)
    - (len(input_data) - buffer_size) ≥ control_data_offset
    - len(input_data) ≥ buffer_size

    If triggered, overwrites memory starting at stack_variable_address with input_data.
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
    # Even if not, still a buffer overflow occurs
    if (len(input_data) - buffer_size) < control_data_offset:
        # Overflow occurs but doesn't necessarily reach control data
        pass

    # Perform the overflow write
    privileged = False  # assume user-level
    result = memory.memory_write(stack_variable_address, input_data, privileged)
    return memory


# Demonstration
if __name__ == "__main__":
    # Use create_memory_state from memory_setup.py to configure memory
    mem = create_memory_state()

    # Assume stack variable address within stack:
    STACK_START = mem.layout["STACK_START"]
    stack_var_addr = STACK_START + 0x50
    buffer_size = 10
    control_data_offset = 5
    input_data = b'A' * 15  # large enough to overflow
    req_perms = Permissions(r=1, w=1, e=0)
    seg_id = SegmentIdentifier("Stack Segment")

    # Trigger overflow
    updated_mem = CWE121_StackBasedBufferOverflow(
        memory=mem,
        memory_segment=seg_id,
        required_permissions=req_perms,
        stack_variable_address=stack_var_addr,
        control_data_offset=control_data_offset,
        input_data=input_data,
        buffer_size=buffer_size
    )

    # Read back to confirm
    try:
        read_back = updated_mem.memory_read(stack_var_addr, 15, privileged=False)
        print("Memory at stack_var_addr after overflow:", read_back)
    except Exception as e:
        print("Error reading memory:", e)