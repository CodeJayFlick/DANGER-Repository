Here is the translation of the Java code to Python:
```python
class MemoryPageBank:
    def __init__(self, address_space: int, big_endian: bool, page_size: int, fault_handler):
        self.page = {}
        super().__init__(address_space, big_endian, page_size, fault_handler)

    def get_page(self, addr: int) -> 'MemoryPage':
        iter = next((iter for k, v in self.page.items() if k == addr), None)
        if iter is None:
            size = self.get_page_size()
            pageptr = MemoryPage(size)
            self.page[addr] = pageptr
            return pageptr
        else:
            return iter[1]

    def set_page(self, addr: int, val: bytes, skip: int, size: int, buf_offset: int):
        if size == self.get_page_size() and buf_offset == 0:
            self.page[addr] = MemoryPage(val)
            return
        pageptr = self.get_page(addr)
        pageptr.data[skip:skip+size] = val[buf_offset:]
        pageptr.set_initialized(skip, size)

    def set_page_initialized(self, addr: int, initialized: bool, skip: int, size: int, buf_offset: int):
        iter = next((iter for k, v in self.page.items() if k == addr), None)
        if iter is None:
            if not initialized:
                return
            pagesize = self.get_page_size()
            pageptr = MemoryPage(pagesize)
            self.page[addr] = pageptr
        else:
            pageptr = iter[1]

        if size == self.get_page_size() and buf_offset == 0:
            if initialized:
                pageptr.set_initialized()
            else:
                pageptr.set_uninitialized()
        elif initialized:
            pageptr.set_initialized(skip, size)
        else:
            pageptr.set_uninitialized(skip, size)

class MemoryPage:
    def __init__(self, data: bytes):
        self.data = data
        self.uninitialized = True

    def set_initialized(self, skip=0, size=None):
        if size is None:
            self.uninitialized = False
        else:
            self.data[skip:skip+size] = b'\x00' * size
            self.uninitialized = False

    def set_uninitialized(self, skip=0, size=None):
        if size is None:
            self.uninitialized = True
        else:
            self.data[skip:skip+size] = b'\xFF' * size
            self.uninitialized = True
```
Note that I've used Python's built-in `bytes` type to represent the page data, and created a separate `MemoryPage` class to encapsulate the page-specific behavior. The `set_page_initialized` method has been modified slightly to handle the case where the entire page is being initialized or uninitialized at once.