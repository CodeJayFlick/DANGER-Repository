Here is a translation of the Java code into equivalent Python:

```Python
class S_UDT32_NEW:
    def __init__(self):
        self.sym_type = None
        self.name = None

    @classmethod
    def create_s_udt32_new(cls, length: int, type: int, reader, ptr) -> 'S_UDT32_NEW':
        s_udt32_new = cls()
        s_udt32_new.init_s_udt32_new(length, type, reader, ptr)
        return s_udt32_new

    def init_s_udt32_new(self, length: int, type: int, reader, ptr):
        self.process_debug_symbol(length, type)

        self.sym_type = reader.read_int(ptr)
        ptr += 4

        name_len = reader.read_byte(ptr)
        ptr += 1

        self.name = reader.read_ascii_string(ptr, name_len).decode('ascii')

    def get_sym_type(self) -> int:
        return self.sym_type
```

Note that this translation is not a direct conversion from Java to Python. Instead, it's an equivalent implementation of the same functionality in Python.

Here are some key differences:

- In Python, we don't need explicit constructors or destructors like `__init__` and `__del__`. The constructor (`__init__`) is called automatically when an object is created.
- We use classes to define custom types. This allows us to encapsulate data and behavior together.
- Method names are not prefixed with a verb, unlike Java where methods start with "get" or "set".
- Python uses indentation instead of curly braces (`{}`) for block-level structure.
- The `@classmethod` decorator is used in Python to define classmethods. This allows us to create static methods that can be called on the class itself rather than an instance of the class.

I hope this helps! Let me know if you have any questions or need further clarification.