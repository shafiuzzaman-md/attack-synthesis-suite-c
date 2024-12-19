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
    USER = auto()  # User-level privilege
    PRIVILEGED = auto()  # Privileged mode

class MemoryState:
    def __init__(self, memory_size, layout):
        self.memory_size = memory_size
        self.memory_bytes = bytearray(memory_size)
        self.layout = layout 
        self.undefined_addresses = set() # Track freed memory

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
        p = Permissions()
        if seg == SegmentType.RESERVED:
            # Reserved: ---(User), r--(Priv)
            if privileged:
                p.r = 1
        elif seg == SegmentType.PROTECTED:
            # Protected: ---(User), rw-(Priv)
            if privileged:
                p.r = 1
                p.w = 1
        elif seg == SegmentType.STACK:
            # Stack: rw-(User & Priv.)
            p.r = 1
            p.w = 1
        elif seg == SegmentType.HEAP:
            # Heap: rw-(User & Priv.)
            p.r = 1
            p.w = 1
        elif seg == SegmentType.DATA:
            # Data: rw-(User & Priv.)
            p.r = 1
            p.w = 1
        elif seg == SegmentType.CODE:
            # Code: r-x(User), rwx(Priv)
            if privileged:
                p.r = 1
                p.w = 1
                p.e = 1
            else:
                p.r = 1
                p.e = 1
        # LOW_MEMORY, UNUSED, INVALID have no access.
        return p

    
    def memory_read(self, target_address: int, length: int, privileged: bool):
        data = bytearray(length)
        for i in range(length):
            addr = target_address + i
            seg = self.identify_segment(addr)
            perms = self.get_permissions(seg, privileged)
            if perms.r == 0:
                raise PermissionError("Permission denied")
            data[i] = self.memory_bytes[addr]
        return bytes(data)
    
    def memory_write(self, target_address: int, data: bytes, privileged: bool):
        length = len(data)
        for i in range(length):
            addr = target_address + i
            seg = self.identify_segment(addr)
            perms = self.get_permissions(seg, privileged)
            if perms.w == 0:
                raise PermissionError("Permission denied")
            self.memory_bytes[addr] = data[i]
        return self

    def memory_alloc(self, allocation_address: int, allocation_size: int):
        # Initialize allocated region to 0x00
        self.memory_bytes[allocation_address:allocation_address + allocation_size] = b'\x00' * allocation_size
        return self

    def memory_free(self, allocation_address: int, allocation_size: int):
        for addr in range(allocation_address, allocation_address + allocation_size):
            # Mark as undefined
            self.undefined_addresses.add(addr)
        return self
