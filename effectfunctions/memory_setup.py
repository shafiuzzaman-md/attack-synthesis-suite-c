# memory_setup.py
# configuration details

from memory_model import MemoryState

def create_memory_state():
    # Define the memory layout
    # Low Memory Area: 4 KB
    # Code Segment: 1020 KB ≈ 1 MB
    # Data Segment: 1 MB
    # Heap Segment: 1 MB
    # Unused Memory (gap after Heap): 1 MB
    # Stack Segment: 1 MB
    # Protected Segment: 64 KB
    # Reserved Segment: ~4 GB (remaining memory up to 0xFFFFFFFF)
    
    layout = {
        "LOW_MEMORY_BASE": 0x00000000,
        "CODE_START":      0x00001000, 
        "DATA_START":      0x00100000, 
        "HEAP_START":      0x00200000, 
        "HEAP_END":        0x00300000,
        "STACK_START":     0x00400000,
        "STACK_END":       0x00500000,
        "PROTECTED_START": 0x00510000,
        "RESERVED_START":  0x00520000,
        "MAX_ADDRESS":     0xFFFFFFFF
    }

    # Initialize MemoryState with a given size (for example, 16MB)
    mem = MemoryState(memory_size=0x01000000, layout=layout)
    return mem
