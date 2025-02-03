from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE122_HeapBasedBufferOverflow(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    heap_alloc_address: int,
    allocated_size: int,
    input_data: bytes,
    user_mode: UserMode
) -> MemoryState:
    """
    Models a Heap-Based Buffer Overflow (CWE-122).

    Constraints:
    - memory_segment.segment_name == "Heap Segment"
    - required_permissions.r == 1 and required_permissions.w == 1 (read & write)
    - 0 < len(input_data)

    :param memory: The current MemoryState.
    :param memory_segment: Identifies which segment we're operating on (should be "Heap Segment").
    :param required_permissions: Permissions needed to read/write in this segment.
    :param heap_alloc_address: Starting address where the heap buffer is allocated.
    :param allocated_size: The size of the allocated buffer in bytes.
    :param input_data: The data to write to the allocated buffer (may overflow if too large).
    :param user_mode: Whether the caller is in user or privileged mode.

    :return: Updated MemoryState after simulating the (potentially overflowing) write.
    """

    # 1. Validate segment and permissions
    if memory_segment.segment_name != "Heap Segment":
        raise ValueError("CWE122: Operation not on the heap segment")
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE122: Required read-write permissions not met")

    # 2. 
    if len(input_data) == 0:
        # No data => no overflow occurs
        return memory

    # 3. Simulate allocating the buffer on the heap
    #    Zero-initialize the allocated region.
    memory = memory.memory_alloc(heap_alloc_address, allocated_size)

    # 4. Write input data to the allocated address
    #    This is the crux of the vulnerability: writing beyond 'allocated_size' can overwrite adjacent memory.
    memory = memory.memory_write(heap_alloc_address, input_data, user_mode)

    return memory
