Here is the translation of the given Java code into equivalent Python:

```Python
import struct

class DmgUtil:
    DMG_MAGIC_BYTES_v1 = b'\xd0\xcf$8\xb8'
    DMG_MAGIC_BYTES_v2 = b'FDSH'

    @staticmethod
    def is_dmg(program):
        if program is not None:
            address = program.min_address()
            if address is not None:
                try:
                    bytes_ = bytearray(8)
                    program.get_memory().get_bytes(address, bytes_)
                    return struct.pack('8B', *bytes_) in (DmgUtil.DMG_MAGIC_BYTES_v1, DmgUtil.DMG_MAGIC_BYTES_v2)
                except Exception:  # Catch all exceptions
                    pass
        return False

```

Note that Python does not have a direct equivalent to Java's `package` declaration. The code is simply defined as a class within the script.

The translation of the given Java method into an equivalent Python function:

- In Java, you can directly access attributes (like `program.getMinAddress()`) and methods (like `getMemory().getBytes(address, bytes)`). In Python, these are replaced with attribute lookups (`program.min_address()`), method calls (`program.get_memory().get_bytes(address, bytes_)`), or function calls.

- Java's `try-catch` block is translated into a try-except block in Python. The exception type to catch can be specified explicitly (like `MemoryAccessException`) or caught as any kind of exception with the keyword `Exception`.

- In Java, you use `Arrays.equals()` to compare arrays. In Python, this is replaced by using the `in` operator on an iterable.

The rest of the code remains mostly unchanged from its original form in Java.