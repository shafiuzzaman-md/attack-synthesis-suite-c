from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE124_BufferUnderwrite(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    buffer_address: int,
    buffer_length: int,
    underwrite_index: int,
    data_to_write: bytes,
    user_mode: UserMode
) -> MemoryState:
    """
    Models CWE-124: Buffer Underwrite (writing before the start of a buffer).

    Steps:
      1. Check the target segment and ensure we have read/write permissions.
      2. "Allocate" a buffer at 'buffer_address' of 'buffer_length' bytes.
      3. Write 'data_to_write' at buffer_address + underwrite_index, 
         which may be negative and thus write before 'buffer_address', 
         corrupting memory.

    Constraints:
    - memory_segment.segment_name in a valid segment for buffer usage (e.g., "Heap Segment", "Stack Segment", etc.)
    - required_permissions must have r=1, w=1
    - buffer_length > 0
    - underwrite_index can be negative (vulnerability)
    - len(data_to_write) >= 1

    :param memory: Current MemoryState.
    :param memory_segment: The segment in which the buffer resides (heap, stack, data, etc.).
    :param required_permissions: Permissions required (needs r=1, w=1).
    :param buffer_address: The start address of the buffer in memory.
    :param buffer_length: The size (in bytes) of the buffer.
    :param underwrite_index: The index (offset from buffer_address) at which to write. If negative, an underwrite occurs.
    :param data_to_write: The data to write, potentially out-of-bounds.
    :param user_mode: Whether the caller is in user or privileged mode.
    :return: Updated MemoryState with the (potentially invalid) write applied.
    """

    # 1. Validate segment name and permissions
    #    We don't strictly require "Heap Segment" or "Stack Segment"—any allocated region can be underwritten.
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE124: Read/write permissions required.")

    if buffer_length <= 0:
        raise ValueError("CWE124: buffer_length must be > 0.")

    if len(data_to_write) == 0:
        # Nothing to write => no vulnerability triggered
        return memory

    # 2. Allocate the buffer (zero-initialize) to simulate a fresh region.
    #    This doesn't protect against writing before 'buffer_address'; it's just part of the normal setup.
    memory = memory.memory_alloc(buffer_address, buffer_length)

    # 3. Compute the absolute address where we will write, ignoring if it's < buffer_address
    #    => This is the core vulnerability if underwrite_index < 0.
    write_address = buffer_address + underwrite_index

    # 4. Perform the write operation, which may be an underwrite.
    #    If 'write_address' < buffer_address, this effectively writes to memory before the buffer’s start.
    memory = memory.memory_write(write_address, data_to_write, user_mode)

    return memory
