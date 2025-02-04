import sys
import os

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)


from memorymodel.memory_setup import create_memory_state
from memorymodel.config import WORD_SIZE
from memorymodel.memory_model import Permissions, UserMode
from effectfunctions.cwe127_effect  import CWE127_BufferUnderread, SegmentIdentifier


def test_cwe127_buffer_underread():


    # 1. Create memory state
    memory = create_memory_state(WORD_SIZE)

    # 2. Define an address for a buffer on the heap
    buffer_address = memory.layout["HEAP_START"]
    buffer_length = 100  # e.g., 100 bytes

    # 3. We'll simulate a negative offset to read before 'buffer_address'
    underread_offset = -8  # e.g., the pointer is 8 bytes before the buffer

    # 4. The size of data we want to read (like a strcpy that copies up to 100 bytes)
    read_size = 50

    # 5. Permissions (r=1 for reading)
    required_permissions = Permissions(r=1, w=1)  # might also do w=0 if we only read

    # 6. Execute the underread effect
    print("=== CWE-127 Buffer Underread Demo ===")
    print(f"Allocating a 100-byte buffer at address {hex(buffer_address)}")
    print(f"Reading {read_size} bytes from offset {underread_offset} (underread)")

    underread_data = CWE127_BufferUnderread(
        memory=memory,
        memory_segment=SegmentIdentifier("Heap Segment"),
        required_permissions=required_permissions,
        buffer_address=buffer_address,
        buffer_length=buffer_length,
        underread_offset=underread_offset,
        read_size=read_size,
        user_mode=UserMode.USER
    )

    # 7. Print or analyze the read data
    print(f"[RESULT] Underread Data: {underread_data}")
    print("=== End of CWE-127 Demo ===")


if __name__ == "__main__":
    test_cwe127_buffer_underread()
