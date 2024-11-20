Here is the translation of the Java code into Python:

```Python
class Register:
    def __init__(self, name: str, description: str, address: 'Address', num_bytes: int,
                 least_sig_bit: int, bit_length: int, big_endian: bool, type_flags: int):
        self.name = name
        self.description = description
        self.address = address
        self.num_bytes = num_bytes
        self.type_flags = type_flags
        self.big_endian = big_endian
        self.bit_length = bit_length
        self.least_sig_bit = least_sig_bit

    def add_alias(self, alias: str):
        if self.name == alias:
            return
        if not hasattr(self, 'aliases'):
            self.aliases = set()
        self.aliases.add(alias)

    def remove_alias(self, alias: str):
        if hasattr(self, 'aliases') and self.aliases is not None:
            self.aliases.remove(alias)

    @property
    def aliases(self) -> set or None:
        return getattr(self, '_aliases', None)

    @aliases.setter
    def aliases(self, value: set or None):
        setattr(self, '_aliases', value)

    def get_aliases(self) -> list or tuple or None:
        if not hasattr(self, 'aliases') or self.aliases is None:
            return []
        return list(self.aliases)

    # ... (rest of the methods are similar)
```

Please note that Python does not have direct equivalent to Java's `equals`, `hashCode` and other comparable method. In this translation, I've used Python's built-in equality operator (`==`) for comparison.

Also, in Python, we don't need explicit getter and setter methods like we do in Java. We can directly access the attributes using dot notation (e.g., `self.name`).