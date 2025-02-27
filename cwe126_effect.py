from memorymodel.memory_model import MemoryState, Permissions, UserMode
from memorymodel.config import WORD_SIZE

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE126_BufferOverread(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    buffer_address: int,
    buffer_length: int,
    index_to_read: int,
    user_mode: UserMode
) -> int:
    """
    Models Buffer Overread

    :param memory: The current MemoryState.
    :param memory_segment: Segment identifier (e.g., "Heap Segment", "Stack Segment").
    :param required_permissions: Permissions needed (requires read).
    :param buffer_address: The starting address of the buffer in memory.
    :param buffer_length: The number of elements allocated in the buffer.
    :param index_to_read: The (potentially invalid) index to read from the buffer.
    :param user_mode: Whether the caller is in USER or PRIVILEGED mode.
    :return: The integer read from the (possibly out-of-bounds) location.
    """

    # 1. Optional segment check
    if memory_segment.segment_name not in ["Heap Segment", "Stack Segment", "Data Segment"]:
        raise ValueError(f"CWE126_BufferOverread_Vuln: Unsupported segment '{memory_segment.segment_name}'")

    # 2. Check read permission
    if required_permissions.r != 1:
        raise PermissionError("CWE126_BufferOverread_Vuln: Read permission not granted")

    # 3. Ignore upper-bound check => POTENTIAL FLAW
    #    We only do a minimal check to ensure index is non-negative.
    if index_to_read < 0:
        raise ValueError("CWE126_BufferOverread_Vuln: Index cannot be negative")

    # 4. Calculate element size from global WORD_SIZE
    element_size_bytes = WORD_SIZE // 8  # e.g., 4 bytes if WORD_SIZE=32

    # 5. Calculate the target address. If index_to_read >= buffer_length, we read out-of-bounds.
    target_address = buffer_address + (index_to_read * element_size_bytes)

    # 6. Perform the read. This may succeed in reading stale or invalid memory if out-of-bounds.
    data_bytes = memory.memory_read(target_address, element_size_bytes, user_mode)

    # 7. Converting data_bytes to an integer (int.from_bytes()) assumes the buffer stores elements in binary format
    return int.from_bytes(data_bytes, byteorder="little")
