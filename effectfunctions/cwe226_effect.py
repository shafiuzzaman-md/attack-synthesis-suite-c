from memorymodel.memory_model import MemoryState, Permissions, UserMode

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE226_SensitiveInformationUnclearedBeforeRelease(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    variable_address: int,
    sensitive_data: bytes,
    user_mode: UserMode
) -> bytes:
    """
    Models CWE-226: Sensitive Information Uncleared Before Release

    Steps:
      1. Write 'sensitive_data' to 'variable_address'.
      2. Call 'memory_retain' to mark that the data is no longer needed, but
         physically remains (un-cleared).
      3. Read back from the same address to demonstrate that the data was never
         cleared and remains accessible.

    Constraints:
    - required_permissions must have r=1 and w=1 (read and write).
    - len(sensitive_data) > 0

    :param memory: Current memory state.
    :param memory_segment: Identifier for the memory segment (Heap, Stack, Data, etc.).
    :param required_permissions: Permissions needed (must have r=1, w=1).
    :param variable_address: The address where the sensitive data is stored.
    :param sensitive_data: The sensitive information to be stored.
    :param user_mode: Whether the caller is in user or privileged mode.
    :return: The raw bytes read back (showing the data was retained).
    """

    # 1. Check read & write permissions
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE226: Required read-write permissions not met")

    # 2. If there's no data, there's no vulnerability to demonstrate
    if len(sensitive_data) == 0:
        return b''

    # 3. Write the sensitive data to the designated address
    memory = memory.memory_write(variable_address, sensitive_data, user_mode)

    # 4. 'Retain' the memory region, simulating that this region is now 'done'
    #    but no clearing action is performed (the data remains physically).
    memory = memory.memory_retain(variable_address, len(sensitive_data))

    # 5. Read back from the same address to show the sensitive data persists
    exposed_data = memory.memory_read(variable_address, len(sensitive_data), user_mode)

    return exposed_data
