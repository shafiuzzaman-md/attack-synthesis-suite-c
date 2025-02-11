from memorymodel.memory_model import MemoryState, Permissions, UserMode

# Typical 32-bit integer boundaries (signed)
INT_MIN = -2147483648
INT_MAX =  2147483647

class SegmentIdentifier:
    def __init__(self, segment_name: str):
        self.segment_name = segment_name

def CWE190_IntegerOverflow_IntAdd(
    memory: MemoryState,
    memory_segment: SegmentIdentifier,
    required_permissions: Permissions,
    integer_address: int,
    input_int: int,
    user_mode: UserMode
) -> MemoryState:
    """
    Models CWE190: Integer Overflow (32-bit int) by adding 1 to 'input_int'.

    Constraints:
    - memory_segment.segment_name = "Data Segment"
    - required_permissions at least rw- (r=1, w=1)
    - INT_MIN ≤ input_int ≤ INT_MAX  (32-bit signed range)
    - integer_address must be a valid address in the data segment (not explicitly checked here)

    If triggered (i.e., if 'input_int' == INT_MAX), this addition would overflow in C.
    In Python, the result goes beyond 32-bit range, but we consider it an overflow scenario.
    """

    # 1. Check segment constraint
    if memory_segment.segment_name != "Data Segment":
        raise ValueError("CWE190: Not in data segment")

    # 2. Check permissions
    if required_permissions.r != 1 or required_permissions.w != 1:
        raise PermissionError("CWE190: Required rw- permissions not met")

    # (Optionally) Validate the input range (if you want to ensure it’s within 32-bit signed)
    if not (INT_MIN <= input_int <= INT_MAX):
        raise ValueError("CWE190: input_int out of 32-bit int range")

    # 3. Write 'input_int' into memory as a 4-byte (32-bit) little-endian integer
    data_bytes = (input_int & 0xFFFFFFFF).to_bytes(4, byteorder="little", signed=False)
    memory = memory.memory_write(integer_address, data_bytes, (user_mode == UserMode.PRIVILEGED))

    # 4. Read back the 4 bytes to confirm or simulate usage
    stored_bytes = memory.memory_read(integer_address, 4, (user_mode == UserMode.PRIVILEGED))
    current_val = int.from_bytes(stored_bytes, byteorder="little", signed=True)

    # 5. Perform the addition, which in C could overflow if current_val == INT_MAX
    result = current_val + 1

    # 6. Write the new result back to memory
    #    In real C, if it overflowed, you'd get wrap-around, but Python won't wrap automatically.
    #    Still, we store the lower 32 bits to mimic potential wrap (comment out if unneeded).
    new_bytes = (result & 0xFFFFFFFF).to_bytes(4, byteorder="little", signed=False)
    memory = memory.memory_write(integer_address, new_bytes, (user_mode == UserMode.PRIVILEGED))

    return memory
