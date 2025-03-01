# memory_model.py
# Memory model with segment identification and permission checks

from enum import Enum, auto

class SegmentType(Enum):
    LOW_MEMORY = auto()
    CODE = auto()
    DATA = auto()
    HEAP = auto()
    UNUSED = auto()
    STACK = auto()
    PROTECTED = auto()
    RESERVED = auto()
    INVALID = auto()

class Permissions:
    def __init__(self, r=0, w=0, e=0):
        self.r = r
        self.w = w
        self.e = e 

class UserMode(Enum):
    USER = auto()       # User-level privilege
    PRIVILEGED = auto() # Privileged mode

class MemoryState:
    def __init__(self, memory_size, layout):
        self.memory_size = memory_size
        self.memory_bytes = bytearray(memory_size)  # All zeros by default
        self.layout = layout
        self.heap_pointer = layout["HEAP_START"]  # Track heap allocation start

        # Undefined and retained memory tracking
        self.undefined_addresses = set()
        self.retained_addresses = set()

    def identify_segment(self, address: int) -> SegmentType:
        L = self.layout
        if address > L["MAX_ADDRESS"]:
            return SegmentType.INVALID
        if address >= L["RESERVED_START"]:
            return SegmentType.RESERVED
        elif address >= L["PROTECTED_START"]:
            return SegmentType.PROTECTED
        elif address >= L["STACK_START"]:
            return SegmentType.STACK
        elif address >= L["HEAP_END"]:
            return SegmentType.UNUSED
        elif address >= L["HEAP_START"]:
            return SegmentType.HEAP
        elif address >= L["DATA_START"]:
            return SegmentType.DATA
        elif address >= L["CODE_START"]:
            return SegmentType.CODE
        elif address >= L["LOW_MEMORY_BASE"]:
            return SegmentType.LOW_MEMORY
        else:
            return SegmentType.INVALID

    def get_permissions(self, seg: SegmentType, privileged: bool) -> Permissions:
        """
        Returns a Permissions object depending on the segment type
        and whether the caller is privileged or not.
        """
        p = Permissions()
        if seg == SegmentType.RESERVED:
            if privileged:
                p.r = 1
        elif seg == SegmentType.PROTECTED:
            if privileged:
                p.r = 1
                p.w = 1
        elif seg == SegmentType.STACK:
            p.r = 1
            p.w = 1
        elif seg == SegmentType.HEAP:
            p.r = 1
            p.w = 1
        elif seg == SegmentType.DATA:
            p.r = 1
            p.w = 1
        elif seg == SegmentType.CODE:
            if privileged:
                p.r = 1
                p.w = 1
                p.e = 1
            else:
                p.r = 1
                p.e = 1
        return p

    def memory_read(self, target_address: int, length: int, privileged: bool):
        data = bytearray(length)
        for i in range(length):
            addr = target_address + i
            seg = self.identify_segment(addr)
            perms = self.get_permissions(seg, privileged)
            if perms.r == 0:
                raise PermissionError("Permission denied (read)")
            data[i] = self.memory_bytes[addr]
        return bytes(data)

    def memory_write(self, target_address: int, data: bytes, privileged: bool):
        length = len(data)
        for i in range(length):
            addr = target_address + i
            seg = self.identify_segment(addr)
            perms = self.get_permissions(seg, privileged)
            if perms.w == 0:
                raise PermissionError("Permission denied (write)")

            if addr in self.undefined_addresses:
                self.undefined_addresses.remove(addr)
            if addr in self.retained_addresses:
                self.retained_addresses.remove(addr)

            self.memory_bytes[addr] = data[i]
        return self

    def memory_alloc(self, allocation_address: int, allocation_size: int):
        """
        Basic 'alloc' that zeroes out the allocated region at a specific address.
        """
        end_addr = allocation_address + allocation_size
        self.memory_bytes[allocation_address:end_addr] = b'\x00' * allocation_size
        for addr in range(allocation_address, end_addr):
            self.undefined_addresses.discard(addr)
            self.retained_addresses.discard(addr)
        return self

    def memory_free(self, allocation_address: int, allocation_size: int):
        """
        Marks a region as undefined (like freeing heap memory).
        """
        for addr in range(allocation_address, allocation_address + allocation_size):
            self.undefined_addresses.add(addr)
        return self

    def heap_alloc(self, allocation_size: int):
        """
        Dynamically allocates 'allocation_size' bytes on the heap.
        Returns (allocated_address, updated_memory_state) or (None, self) if allocation fails.
        """
        if allocation_size <= 0:
            return None, self  # Zero or negative allocation is invalid

        allocation_address = self.heap_pointer
        end_addr = allocation_address + allocation_size

        if end_addr > self.layout["HEAP_END"]:
            return None, self  # Out of heap memory

        self.memory_bytes[allocation_address:end_addr] = b'\x00' * allocation_size

        self.heap_pointer = end_addr  # Move heap forward

        for addr in range(allocation_address, end_addr):
            self.undefined_addresses.discard(addr)
            self.retained_addresses.discard(addr)

        return self

    def heap_free(self, allocation_address: int, allocation_size: int):
        """
        Frees a previously allocated heap region.
        """
        if allocation_address < self.layout["HEAP_START"] or allocation_address + allocation_size > self.layout["HEAP_END"]:
            return self  # Ignore invalid frees

        for addr in range(allocation_address, allocation_address + allocation_size):
            self.undefined_addresses.add(addr)  # Mark freed addresses

        return self  # Return updated memory state

    def memory_stack_release(self, stack_address: int, release_size: int):
        """
        Marks a region in the stack segment as undefined (like returning from a function).
        """
        for offset in range(release_size):
            addr = stack_address + offset
            segment_type = self.identify_segment(addr)
            if segment_type != SegmentType.STACK:
                raise ValueError(
                    f"memory_stack_release: Address {addr} not in stack segment "
                    f"(detected '{segment_type.name}')"
                )
            self.undefined_addresses.add(addr)
        return self

    def memory_retain(self, start_address: int, size: int):
        """
        Marks a region as 'retained' — meaning logically 'released' or 'out of use',
        but the bytes remain intact. This simulates failing to clear sensitive data
        upon free/release. The data remains physically readable.
        """
        for addr in range(start_address, start_address + size):
            if addr not in self.undefined_addresses:
                self.retained_addresses.add(addr)
        return self

    def get_stack_top(self) -> int:
        if self.stack_top is None:
            raise ValueError("Stack is empty or not initialized")
        return self.stack_top
