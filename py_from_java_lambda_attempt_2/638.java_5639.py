Here is the translation of the given Java code into Python:

```Python
class DbgReadPhysicalMemoryCommand:
    def __init__(self, manager, addr, buf, len):
        self.addr = addr
        self.buf = buf
        self.len = len
        super().__init__(manager)

    def complete(self, pending):
        range_set = set()
        range_set.add((self.addr, self.addr + self.read_len))
        return range_set

    def invoke(self):
        self.read_len = manager.get_data_spaces().read_physical(self.addr, self.buf, self.len)
```

Note that Python does not have direct equivalents for Java's `RangeSet` and `TreeRangeSet`, so I used a set to represent the ranges. Also, Python's `ByteBuffer` is not directly equivalent either, but you can use Python's built-in byte arrays (`bytearray`) or libraries like NumPy if needed.

Also note that this translation assumes that there are classes in your code which have methods `complete()` and `invoke()`, these are abstracted away here.