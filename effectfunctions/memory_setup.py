from memory_model import MemoryState

def create_memory_state(word_size: int):
    if word_size == 32:
        total_memory = 0x01000000  # 16MB
        max_address = 0xFFFFFFFF
    elif word_size == 64:
        total_memory = 0x02000000  # 32MB
        max_address = 0xFFFFFFFFFFFFFFFF
    else:
        raise ValueError("Unsupported word size: Use 32 or 64")

    # Define relative sizes for each segment
    low_memory_size = int(total_memory * 0.001)  # 0.1% of total memory
    code_segment_size = int(total_memory * 0.1)  # 10% of total memory
    data_segment_size = int(total_memory * 0.2)  # 20% of total memory
    heap_segment_size = int(total_memory * 0.2)  # 20% of total memory
    unused_segment_size = int(total_memory * 0.2)  # 20% of total memory
    stack_segment_size = int(total_memory * 0.2)  # 20% of total memory
    protected_segment_size = int(total_memory * 0.05)  # 5% of total memory

    # Calculate base addresses for each segment
    low_memory_base = 0x00000000
    code_start = low_memory_base + low_memory_size
    data_start = code_start + code_segment_size
    heap_start = data_start + data_segment_size
    heap_end = heap_start + heap_segment_size
    stack_start = heap_end + unused_segment_size
    stack_end = stack_start + stack_segment_size
    protected_start = stack_end
    reserved_start = protected_start + protected_segment_size

    layout = {
        "LOW_MEMORY_BASE": low_memory_base,
        "CODE_START":      code_start,
        "DATA_START":      data_start,
        "HEAP_START":      heap_start,
        "HEAP_END":        heap_end,
        "STACK_START":     stack_start,
        "STACK_END":       stack_end,
        "PROTECTED_START": protected_start,
        "RESERVED_START":  reserved_start,
        "MAX_ADDRESS":     max_address
    }

    return MemoryState(memory_size=total_memory, layout=layout)
