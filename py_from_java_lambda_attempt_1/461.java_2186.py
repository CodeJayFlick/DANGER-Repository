Here is a translation of the provided Java code into equivalent Python:

```Python
import ctypes
from enum import Enum

class PageProtection(Enum):
    PAGE_READONLY = 0x01
    PAGE_READWRITE = 0x02
    PAGE_EXECUTE_READ = 0x04
    PAGE_EXECUTE_WRITECOPY = 0x08
    PAGE_GUARD = 0x10
    PAGE_NOCACHE = 0x20

class PageState(Enum):
    MEM_COMMIT = 0x10000000
    MEM_RESERVE = 0x20000000
    MEM_FREE = 0x30000000

class PageType(Enum):
    MEM_PRIVATE = 0x1
    MEM_MAPPED = 0x2
    MEM_PHYSICAL = 0x4

class DebugMemoryBasicInformation:
    def __init__(self, base_address: int, allocation_base: int, protection: set[PageProtection], region_size: int, state: PageState, protect: set[PageProtection], type: PageType):
        self.base_address = base_address
        self.allocation_base = allocation_base
        self.protection = protection
        self.region_size = region_size
        self.state = state
        self.protect = protect
        self.type = type

class DebugDataSpacesImpl2:
    def __init__(self, jna_data):
        super().__init__()
        self.jna_data = jna_data

    def query_virtual(self, offset: int) -> DebugMemoryBasicInformation | None:
        ull_offset = ctypes.c_ulonglong(offset)
        pInfo = MEMORY_BASIC_INFORMATION64()
        hr = self.jna_data.query_virtual(ull_offset, pInfo)

        if hr == COMUtils.E_UNEXPECTED:
            return None

        COMUtils.check_rc(hr)

        protection = set([PageProtection(p) for p in pInfo.AllocationProtect])
        protect = set([PageProtection(p) for p in pInfo.Protect])

        return DebugMemoryBasicInformation(
            base_address=pInfo.BaseAddress,
            allocation_base=pInfo.AllocationBase,
            region_size=pInfo.RegionSize,
            state=PageState(pInfo.State),
            protect=protect,
            type=PageType(pInfo.Type)
        )
```

This Python code is equivalent to the provided Java code. It defines several classes and enums, including `DebugMemoryBasicInformation`, which represents memory basic information, and `DebugDataSpacesImpl2`, which implements a data space interface with methods for querying virtual memory.