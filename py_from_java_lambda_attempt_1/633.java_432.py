Here is the translation of the given Java code into equivalent Python:

```Python
class DbgReadBusDataCommand:
    def __init__(self, manager, addr, buf, len, bus_data_type, bus_number, slot_number):
        self.addr = addr
        self.buf = buf
        self.len = len
        self.bus_data_type = bus_data_type
        self.bus_number = bus_number
        self.slot_number = slot_number

    def complete(self, pending=None) -> set:
        return {range(self.addr, self.addr + self.read_len)}

    def invoke(self):
        read_len = manager.get_data_spaces().read_bus_data(
            self.bus_data_type,
            self.bus_number,
            self.slot_number,
            self.addr,
            self.buf,
            self.len
        )
```

Note that this Python code does not include the `AbstractDbgCommand` class or its methods, as these are specific to Java and do not have a direct equivalent in Python. The translation focuses on converting the core logic of the original Java code into Python.

Also note that I used the built-in set data structure for representing the range set (equivalent to Java's `RangeSet<Long>`), which is a collection of unique elements, including ranges.