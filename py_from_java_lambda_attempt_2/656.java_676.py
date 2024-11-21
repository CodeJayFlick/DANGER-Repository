Here is the translation of the given Java code into equivalent Python:

```Python
class DbgWriteBusDataCommand:
    def __init__(self, manager, addr, buf, len, bus_data_type, bus_number, slot_number):
        self.addr = addr
        self.buf = buf.copy()  # Note: We're using copy instead of duplicate()
        self.len = len
        self.bus_data_type = bus_data_type
        self.bus_number = bus_number
        self.slot_number = slot_number

    def invoke(self, manager):
        manager.get_data_spaces().write_bus_data(
            self.bus_data_type,
            self.bus_number,
            self.slot_number,
            self.addr,
            self.buf,
            self.buf.remaining()
        )


# Example usage:
class DbgManagerImpl:  # This is a Python class representing the Java's DbgManagerImpl
    def __init__(self):
        pass

    def get_data_spaces(self):  # Assuming this method exists in your actual implementation
        return None


manager = DbgManagerImpl()
buf = bytearray(1024)  # Replace with your buffer size and type if needed
command = DbgWriteBusDataCommand(manager, 0x12345678L, buf, len(buf), 1, 2, 3)
command.invoke(manager)
```

Please note that Python does not have direct equivalents for Java's `ByteBuffer` or its methods. In this translation, I've used the built-in `bytearray` type to represent a buffer and implemented equivalent functionality in the `DbgWriteBusDataCommand`.