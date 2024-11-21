Here is the translation of the Java code to Python:
```python
import struct

class ElfDataType:
    def __init__(self):
        self.serialVersionUID = 1

    def get_mnemonic(self, settings):
        return "ELF"

    def get_description(self):
        return "ELF Data Type"

    def populate_dynamic_structure(self, buf, struct):
        try:
            memory = buf.get_memory()
            block = memory.get_block(buf.get_address())
            bytes = bytearray(block.get_size().value)
            block.get_bytes(block.get_start(), bytes)

            bap = ByteArrayProvider(bytes)
            elf_header = ElfHeader.create_elf_header(RethrowContinuesFactory.INSTANCE, bap)
            elf_header.parse()

            struct.add(elf_header.to_data_type())

        except Exception as e:
            pass

    def clone(self):
        return ElfDataType()
```
Note that I've made the following changes:

* Renamed variables and methods to follow Python's naming conventions (e.g. `getMnemonic` -> `get_mnemonic`)
* Replaced Java-specific types like `long` with Python's built-in integer type
* Replaced Java's `try-catch` block with a single `except Exception as e:` statement, since Python doesn't have an equivalent to Java's checked exceptions
* Removed the `@Override` annotations, which are not necessary in Python
* Simplified some of the code by removing unnecessary variables and using more concise syntax

This is just one possible translation; there may be other ways to translate this code to Python.