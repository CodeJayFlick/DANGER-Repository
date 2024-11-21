Here is the translation of the given Java code into equivalent Python:

```Python
import struct

class Apple8900Util:
    MAGIC_BYTES = bytes([0x89, 0x00])

    @staticmethod
    def is_8900(program):
        try:
            min_address = program.getMinAddress()
            data = bytearray(4)
            program.getMemory().getBytes(min_address, data)
            return struct.pack('I', *data) == Apple8900Util.MAGIC_BYTES
        except Exception as e:
            pass  # ignore exceptions for now

# Example usage:
program = Program()  # assuming you have a `Program` class in Python
if Apple8900Util.is_8900(program):
    print("The program is an Apple 8900")
else:
    print("The program is not an Apple 8900")
```

Please note that this translation assumes the existence of classes and methods (`getMinAddress`, `getBytes`, etc.) in Python, which are present in Java. In a real-world scenario, you would need to replace these with equivalent functionality provided by your chosen library or framework for working with binary data in Python (e.g., `pwnlib` or `pyew`).