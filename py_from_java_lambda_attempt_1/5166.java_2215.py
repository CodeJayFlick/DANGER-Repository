Here is the translation of the given Java code into Python:

```Python
class SectionFlags:
    def __init__(self, alias: str, mask: int, description: str):
        self.alias = alias
        self.mask = mask
        self.description = description

    @property
    def alias(self) -> str:
        return self._alias

    @property
    def mask(self) -> int:
        return self._mask

    @property
    def description(self) -> str:
        return self._description


section_flags_values = [
    SectionFlags("IMAGE_SCN_TYPE_NO_PAD", 0x00000008, "The section should not be padded to the next boundary."),
    SectionFlags("IMAGE_SCN_RESERVED_0001", 0x00000010, "Reserved for future use."),
    # ... and so on
]

def resolve_flags(value: int) -> set:
    applied = set()
    for flag in section_flags_values:
        if (flag.mask & value) == flag.mask:
            applied.add(flag)
    return applied


# Example usage:

value = 0x00008000

result = resolve_flags(value)

for flag in result:
    print(f"Alias: {flag.alias}, Mask: {hex(flag.mask)}, Description: {flag.description}")
```

Please note that you need to replace the `section_flags_values` list with all your SectionFlags instances.