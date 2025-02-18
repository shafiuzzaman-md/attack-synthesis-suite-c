from memorymodel.memory_model import Permissions


class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name


def CWE562_Return_of_Stack_Variable_Address__return_pointer_buf_01_bad(
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    stack_variable_address: int
) -> int:
    """
    Models CWE 562: Return of Stack Variable Address.

    Returns the leaked stack variable address if constraints are met.
    """
    # Check constraints
    if memory_segment.segment_name != "Stack Segment":
        raise ValueError("CWE562: Not in stack segment")

    if required_permissions.r != 1:
        raise PermissionError("CWE562: Read permission required")

    # Leak the stack address
    return stack_variable_address
