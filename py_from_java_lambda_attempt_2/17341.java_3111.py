Here's your Java code translated into equivalent Python:

```Python
class SetSystemModePlan:
    def __init__(self):
        self.is_read_only = False
        super().__init__(False, "SET_SYSTEM_MODE")

    def __init__(self, is_read_only=False):
        self.is_read_only = is_read_only if is_read_only else False
        super().__init__(False, "SET_SYSTEM_MODE")

    @property
    def paths(self):
        return []

    @property
    def is_read_only_(self):
        return self.is_read_only

    def serialize_to_stream(self, stream):
        stream.write_byte(ord("SET_SYSTEM_MODE"))
        stream.write_bool(self.is_read_only)
        if hasattr(stream, 'write_long'):
            stream.write_long(0)  # index
        else:
            stream.write_int(int(0))  # index

    def serialize_to_buffer(self, buffer):
        buffer.put(bytearray([ord("SET_SYSTEM_MODE")]))
        ReadWriteIOUtils.write(buffer, self.is_read_only)
        if hasattr(buffer, 'put_long'):
            buffer.put_long(0)  # index
        else:
            buffer.putInt(int(0))  # index

    def deserialize_from_buffer(self, buffer):
        try:
            self.is_read_only = bool(buffer.get())
            self.index = buffer.get_long()
        except Exception as e:
            raise IllegalPathException(str(e))
```

Note that Python doesn't have direct equivalents for Java's `DataOutputStream` and `ByteBuffer`. Instead, we use the built-in file I/O functions (`open`, `read`, `write`) or libraries like `struct` to handle serialization.