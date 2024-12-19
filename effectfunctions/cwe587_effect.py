from memory_model import MemoryState, Permissions
from config import WORD_SIZE  # Import the shared word size

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name


def CWE587_AssignmentOfFixedAddressToPointer(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    pointer_variable_address: int,
    fixed_address: int
) -> int:
    """
    Models CWE 587: Assignment of Fixed Address to Pointer.

    Updates a pointer variable to point to a fixed address in memory.
    """
    # Check constraints
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE587: Read-write permission required")

    # Write the fixed address into the pointer variable
    memory = memory.memory_write(
        target_address=pointer_variable_address,
        data=fixed_address.to_bytes(WORD_SIZE, 'little'),  # Assuming 32-bit address
        privileged=False
    )

    # Confirm the updated pointer
    updated_pointer = int.from_bytes(
        memory.memory_read(pointer_variable_address, WORD_SIZE, privileged=False),
        'little'
    )
    return updated_pointer
