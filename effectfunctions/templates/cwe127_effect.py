from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE127_BufferUnderread(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    buffer_address: int,
    buffer_length: int,
    underread_offset: int,
    read_size: int,
    user_mode: UserMode
) -> bytes:
    """
    Models CWE-127: Buffer Underread.

    Steps:
      1. Allocate a buffer at 'buffer_address' of length 'buffer_length'.
      2. Compute an underread address = buffer_address + underread_offset.
         If 'underread_offset' is negative, that address is before the start of the buffer.
      3. Read 'read_size' bytes from that address, returning the potentially invalid data.

    Constraints:
      - memory_segment.segment_name is valid for reading (e.g., "Heap Segment", "Stack Segment").
      - required_permissions.r == 1 (read permission).
      - buffer_length > 0
      - read_size > 0
      - underread_offset could be negative (vulnerability).
      - The user_mode determines if privileged or user-level checks apply.

    :param memory: The MemoryState (with layout, memory_bytes, etc.).
    :param memory_segment: Identifies which segment we are operating on (Heap, Stack, etc.).
    :param required_permissions: The read (and optionally write) permissions needed.
    :param buffer_address: The start address of the allocated buffer in memory.
    :param buffer_length: The total size (in bytes) of the buffer.
    :param underread_offset: Offset from 'buffer_address' at which to begin reading.
                             If negative, we read before the buffer's base.
    :param read_size: Number of bytes to read from that underread address.
    :param user_mode: Whether this is user or privileged mode.
    :return: The raw bytes read from the underread address.
    """

    # 1. Validate permissions
    if required_permissions.r != 1:
        raise PermissionError("CWE127: Read permission is required.")

    if buffer_length <= 0:
        raise ValueError("CWE127: buffer_length must be > 0.")

    if read_size <= 0:
        raise ValueError("CWE127: read_size must be > 0.")

    # 2. Simulate allocating the buffer. This zero-initializes 'buffer_length' bytes
    #    starting at 'buffer_address'.
    memory = memory.memory_alloc(buffer_address, buffer_length)

    # 3. Calculate the underread address
    underread_address = buffer_address + underread_offset

    # 4. Perform the read. If 'underread_offset' is negative, 'underread_address' < buffer_address.
    #    This is the core vulnerability: reading from memory before the allocated region.
    data = memory.memory_read(underread_address, read_size, (user_mode == UserMode.PRIVILEGED))

    return data
