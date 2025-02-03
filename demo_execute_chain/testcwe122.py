import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

from memorymodel.memory_setup import create_memory_state
from memorymodel.config import WORD_SIZE
from memorymodel.memory_model import Permissions, UserMode
from effectfunctions.cwe122_effect import CWE122_HeapBasedBufferOverflow, SegmentIdentifier

def test_cwe122_heap_overflow():
    # 1. Initialize memory
    memory = create_memory_state(WORD_SIZE)

    # 2. Define heap address and size
    heap_address = memory.layout["HEAP_START"]
    allocated_size = 50  # e.g., 50 bytes

    # 3. Create input data larger than allocated_size to force an overflow
    input_data = b"A" * 100  # 100 bytes

    # 4. Required read-write permissions
    required_permissions = Permissions(r=1, w=1)

    # 5. Execute the heap overflow effect
    print("=== CWE-122 Heap-Based Buffer Overflow Demo ===")
    print(f"Allocating {allocated_size} bytes at heap address {hex(heap_address)}")
    print(f"Attempting to write {len(input_data)} bytes (overflow expected)...")

    updated_memory = CWE122_HeapBasedBufferOverflow(
        memory=memory,
        memory_segment=SegmentIdentifier("Heap Segment"),
        required_permissions=required_permissions,
        heap_alloc_address=heap_address,
        allocated_size=allocated_size,
        input_data=input_data,
        user_mode=UserMode.USER
    )

    # 6. 
    try:
        read_back = updated_memory.memory_read(heap_address, 120, privileged=False)
        print(f"[RESULT] Memory after overflow write: {read_back}")
    except Exception as e:
        print(f"[ERROR] Reading memory: {e}")

    print("=== End of CWE-122 Demo ===")


if __name__ == "__main__":
    test_cwe122_heap_overflow()
