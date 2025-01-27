import sys
import os

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)


from memorymodel.memory_setup import create_memory_state
from memorymodel.memory_model import Permissions, UserMode
from memorymodel.config import WORD_SIZE
from effectfunctions.cwe126_effect import CWE126_BufferOverread, SegmentIdentifier

def test_cwe126_buffer_overread_vuln():
    """
    Test CWE126_BufferOverread_Vuln function for both valid and out-of-bounds reads.
    """

    # Step 1: Initialize memory
    memory = create_memory_state(WORD_SIZE)

    # Step 2: Allocate a buffer in the heap
    buffer_address = memory.layout["HEAP_START"]
    buffer_length = 5  # Number of elements in the buffer
    element_size = WORD_SIZE // 8  # Size of each element in bytes

    # Step 3: Write integer values [0, 1, 2, 3, 4] to the buffer
    for i in range(buffer_length):
        value_bytes = i.to_bytes(element_size, byteorder="little")
        memory.memory_write(buffer_address + i * element_size, value_bytes, privileged=False)

    print("=== CWE-126 Buffer Overread Test ===")
    print(f"Buffer start address: {hex(buffer_address)}")
    print(f"Buffer length: {buffer_length} elements (word size: {WORD_SIZE}-bit)")

    # Step 4: Perform valid reads within bounds
    print("\n[INFO] Valid Reads:")
    for index in range(buffer_length):
        try:
            value = CWE126_BufferOverread(
                memory=memory,
                memory_segment=SegmentIdentifier("Heap Segment"),
                required_permissions=Permissions(r=1, w=0),
                buffer_address=buffer_address,
                buffer_length=buffer_length,
                index_to_read=index,
                user_mode=UserMode.USER
            )
            print(f"Value at index {index}: {value}")
        except Exception as e:
            print(f"[ERROR] Failed to read index {index}: {e}")

    # Step 5: Perform an out-of-bounds read
    out_of_bounds_index = buffer_length + 2  # Deliberately beyond the buffer's length
    print("\n[INFO] Out-of-Bounds Read:")
    try:
        value = CWE126_BufferOverread(
            memory=memory,
            memory_segment=SegmentIdentifier("Heap Segment"),
            required_permissions=Permissions(r=1, w=0),
            buffer_address=buffer_address,
            buffer_length=buffer_length,
            index_to_read=out_of_bounds_index,
            user_mode=UserMode.USER
        )
        print(f"[VULNERABILITY] Value at out-of-bounds index {out_of_bounds_index}: {value}")
    except Exception as e:
        print(f"[ERROR] Failed to read out-of-bounds index {out_of_bounds_index}: {e}")

    print("\n=== End of Test ===")


if __name__ == "__main__":
    test_cwe126_buffer_overread_vuln()