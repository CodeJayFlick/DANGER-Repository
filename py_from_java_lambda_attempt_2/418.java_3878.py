Here is the equivalent Python code:

```Python
class DebugSymbolEntry:
    def __init__(self, module_base: int, offset: int, symbol_id: int, size: int, flags: int, type_id: int, name: str, tag: int):
        self.module_base = module_base
        self.offset = offset
        self.symbol_id = symbol_id
        self.size = size
        self.flags = flags
        self.type_id = type_id
        self.name = name
        self.tag = tag

    def __str__(self) -> str:
        return f"<DebugSymbolEntry {hex(self.module_base)}:{hex(self.symbol_id)}\n" \
               f"  offset={hex(self.offset)},\n" \
               f"  size=0x{x:04x},\n" \
               f"  flags=0x{self.flags:x},\n" \
               f"  type_id=0x{self.type_id:x},\n" \
               f"  name='{self.name}',\n" \
               f"  tag=0x{x:04x}>"
```

Note that I've used Python's built-in `int` and `str` types, as well as the `f-string` formatting syntax to create a string representation of each object.