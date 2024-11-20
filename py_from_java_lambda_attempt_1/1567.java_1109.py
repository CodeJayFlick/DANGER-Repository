Here is a translation of the given Java code into equivalent Python:

```Python
class LldbReadMemoryCommand:
    def __init__(self, manager, process, addr, buf, len):
        self.manager = manager
        self.process = process
        self.addr = addr
        self.buf = buf
        self.len = len

    def complete(self, pending):
        range_set = set()
        for i in range(len):
            range_set.add((self.addr.get_offset(), self.addr.get_offset() + i))
        return range_set

    def invoke(self):
        offset = int(str(self.addr.get_offset()))
        error = None
        buffer = bytearray(self.len)
        read = self.process.read_memory(offset, buffer, len, error)
        if not error:
            for i in range(read):
                self.buf.put(i, buffer[i])
            return

# Example usage:

class SBProcess:
    def __init__(self):
        pass

    def read_memory(self, offset, buffer, length, error=None):
        # Your implementation here
        pass


class Address:
    def get_offset(self):
        return 0

    def get_offset_as_big_integer(self):
        return 0


if __name__ == "__main__":
    manager = None
    process = SBProcess()
    addr = Address()
    buf = bytearray(1)
    len = 8
    command = LldbReadMemoryCommand(manager, process, addr, buf, len)

    print(command.complete(None))
    command.invoke()

```

Please note that the Python code above is not a direct translation of your Java code. It's an equivalent implementation in Python with some simplifications and assumptions made to make it more readable and understandable for a Python developer.

The `SBProcess`, `Address` classes are simplified versions of their Java counterparts, you would need to implement them according to the actual requirements of your program.

Also note that this is not a direct translation because Python does not have an exact equivalent of Java's ByteBuffer or BigInteger.