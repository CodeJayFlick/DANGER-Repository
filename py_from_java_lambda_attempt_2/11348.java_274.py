Here is a translation of the provided Java code into equivalent Python:

```Python
class MemoryImage:
    def __init__(self, spc, is_big_endian, ps, ld):
        self.spc = spc
        self.is_big_endian = is_big_endian
        self.ps = ps
        self.ld = ld

    def get_page(self, addr):
        page = [0] * (self.get_page_size())
        # Assume that -addr- is page aligned
        mask_update = self.ld.load_fill(page, self.get_page_size(), self.spc.get_address(addr), 0, True)
        return MemoryPage(page)

    def set_page(self, addr, val, skip, size, buf_offset):
        self.ld.write_back(val, size, self.spc.get_address(addr), buf_offset)


class MemoryPage:
    def __init__(self, page_size):
        self.page_size = page_size
        self.data = [0] * (page_size)
        self.initialized = False

    def set_initialized(self, initialized, skip, size, buf_offset):
        # unsupported


# usage example:

spc = "some address space"
is_big_endian = True
ps = 4096
ld = MemoryLoadImage()  # this is a placeholder for the actual load image class
mi = MemoryImage(spc, is_big_endian, ps, ld)
page = mi.get_page(0)  # get page at address 0
# set page at some other address (note: write_back method not implemented in above code)
```

Please note that Python does not have direct equivalent of Java's `MemoryBank`, `AddressSpace` and `MemoryLoadImage`. The provided translation is based on the understanding of these classes from their usage within the given Java code.