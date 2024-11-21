Here is the translation of the given Java code into equivalent Python:

```Python
class DbgWriteControlCommand:
    def __init__(self, manager, addr, buf, len, processor):
        self.addr = addr
        self.processor = processor
        self.buf = buf.copy()  # Assuming a similar functionality as duplicate()
        self.len = len

    def invoke(self):
        manager.get_data_spaces().write_control(processor, addr, buf, buf.remaining())
```

Please note that Python does not have direct equivalents for Java's ByteBuffer and DataSpaces. The equivalent in Python would be using the built-in bytes type or a library like numpy to represent binary data. Also, Python doesn't support multiple inheritance (like Java), so you might need to create separate classes if needed.

Here is an example of how you could use Python's bytes class:

```Python
class DbgWriteControlCommand:
    def __init__(self, manager, addr, buf, len, processor):
        self.addr = addr
        self.processor = processor
        self.buf = bytearray(buf)  # Assuming a similar functionality as duplicate()
        self.len = len

    def invoke(self):
        data_spaces = manager.get_data_spaces()
        data_spaces.write_control(processor, addr, bytes(self.buf[:self.len]), self.len)
```

This is just one possible way to translate the given Java code into Python. The actual implementation might vary depending on your specific requirements and constraints.