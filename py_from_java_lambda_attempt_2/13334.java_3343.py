Here is the translation of the Java code to Python:
```python
class PIC30ElfRelocationContext:
    def __init__(self, handler, load_helper, relocation_table, symbol_map):
        super().__init__(handler, load_helper, relocation_table, symbol_map)

    @staticmethod
    def is_debug_section(overlay_space):
        name = overlay_space.name
        return name.startswith(".debug_") or name == ".comment"

    def get_relocation_address(self, base_address, reloc_offset):
        if not base_address.is_loaded_memory_address() and self.is_debug_section(base_address.address_space):
            reloc_offset >>= 1
        return base_address.add_wrap(reloc_offset)
```
Note that I've used the following Python features:

* Classes with `__init__` method to initialize objects.
* Static methods using the `@staticmethod` decorator.
* Inheritance from a parent class (`super().__init__()`) in the constructor.
* Method overriding (the `get_relocation_address` method).
* Bitwise operations (`>>=`) for shifting integers.

I've also replaced Java-specific types and functions with their Python equivalents:

* `package ghidra.app.util.bin.format.elf.relocation;` is not needed, as we're defining a single class.
* `import java.util.Map;` becomes no-op in Python (we don't need to import the `Map` type).
* Java-specific types like `ElfRelocationContext`, `AddressSpace`, and `Address` are replaced with equivalent Python constructs.

Please note that this translation is not perfect, as some details might be lost during the conversion process.