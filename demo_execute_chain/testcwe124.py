import sys
import os

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

from memorymodel.memory_setup import create_memory_state
from memorymodel.config import WORD_SIZE
from memorymodel.memory_model import Permissions, UserMode
from effectfunctions.cwe124_effect import CWE124_BufferUnderwrite, SegmentIdentifier

def test_cwe124_buffer_underwrite():
    # 1. Initialize memory
    memory = create_memory_state(WORD_SIZE)

    # 2. Define an address for the "allocated" buffer (heap, stack, or data—here we use the heap)
    buffer_address = memory.layout["HEAP_START"]
    buffer_length = 10  # e.g., 10 bytes

    # 3. Attempt a negative index to underwrite the buffer
    underwrite_index = -5  # Writes 5 bytes before buffer_address

    # 4. Data to write
    data_to_write = b"XYZ"  # Just 3 bytes for demonstration

    # 5. Permissions
    required_permissions = Permissions(r=1, w=1)

    # 6. Perform the underwrite
    print("=== CWE-124 Buffer Underwrite Demo ===")
    print(f"Allocating {buffer_length} bytes at address {hex(buffer_address)}")
    print(f"Attempting to write {data_to_write} at index {underwrite_index} (underwriting buffer start).")

    updated_memory = CWE124_BufferUnderwrite(
        memory=memory,
        memory_segment=SegmentIdentifier("Heap Segment"),
        required_permissions=required_permissions,
        buffer_address=buffer_address,
        buffer_length=buffer_length,
        underwrite_index=underwrite_index,
        data_to_write=data_to_write,
        user_mode=UserMode.USER
    )

    # 7. Examine memory around 'buffer_address - 5' to see overwritten data
    #    We'll read 15 bytes from a region that starts before the buffer.
    read_start = buffer_address - 5
    read_size = buffer_length + 5  # total region
    try:
        raw_data = updated_memory.memory_read(read_start, read_size, privileged=False)
        print(f"[RESULT] Memory around buffer: {raw_data}")
    except Exception as e:
        print(f"[ERROR] Reading memory region: {e}")

    print("=== End of CWE-124 Demo ===")


if __name__ == "__main__":
    test_cwe124_buffer_underwrite()
