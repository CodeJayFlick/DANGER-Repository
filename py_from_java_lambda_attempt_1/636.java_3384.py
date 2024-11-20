Here is the translation of the given Java code into Python:

```Python
class DbgReadIoCommand:
    def __init__(self, manager, addr, buf, len, interface_type, bus_number, address_space):
        self.addr = addr
        self.buf = buf
        self.len = len
        self.interface_type = interface_type
        self.bus_number = bus_number
        self.address_space = address_space

    def complete(self, pending):
        range_set = set()
        range_set.add((self.addr, self.addr + self.read_len))
        return range_set

    def invoke(self):
        self.read_len = manager.get_data_spaces().read_io(
            self.interface_type,
            self.bus_number,
            self.address_space,
            self.addr,
            self.buf,
            self.len
        )


class DbgManagerImpl:
    def get_data_spaces(self):
        pass


# Example usage:

manager = DbgManagerImpl()
command = DbgReadIoCommand(manager, 0x12345678, bytearray(1024), 1024, 1, 2, 3)
command.invoke()

```

Please note that Python does not have direct equivalent of Java's `ByteBuffer` and `RangeSet`. In the above code, I used Python's built-in `bytearray` for representing a buffer. For implementing `RangeSet`, you can use Python's set data structure to store ranges as tuples.

Also, in this translation, I assumed that `DbgManagerImpl` is another class which has an attribute or method named `get_data_spaces`. You may need to adjust the code based on your actual implementation of these classes.