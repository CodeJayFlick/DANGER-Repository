Here is the translation of the given Java code into Python:

```Python
class Range:
    def __init__(self, space: 'AddrSpace', first: int, last: int):
        self.space = space
        self.first = first
        self.last = last

    @property
    def get_space(self) -> 'AddrSpace':
        return self.space

    @property
    def get_first(self) -> int:
        return self.first

    @property
    def get_last(self) -> int:
        return self.last

    def get_first_addr(self):
        return Address(self.space, self.first)

    def get_last_addr(self):
        return Address(self.space, self.last)

    def __lt__(self, other: 'Range') -> bool:
        if not isinstance(other, Range):
            raise TypeError("Other must be a Range")
        result = self.space.__eq__(other.space)
        if result is False:
            return result
        return self.first < other.first

    @staticmethod
    def print_bounds(s: object) -> None:
        s.write(f"{self.space.name}: {hex(self.first)}-{hex(self.last)}")

    @staticmethod
    def save_xml(s: object, space_name: str = '', first: int = 0, last: int = -1):
        if not isinstance(space_name, str):
            raise TypeError("Space name must be a string")
        s.write(f"<range {space_name} first={first} last={last}/>\n")

    def get_last_addr_open(self, trans) -> 'Address':
        curspc = self.space
        curlast = self.last
        if curlast == curspc.get_mask():
            curspc = trans.next_space_in_order(curspc)
            curlast = 0
        else:
            curlast += 1

        return Address(curspc, curlast)

    def restore_xml(self, el: object, trans) -> None:
        self.space = None
        self.first = 0
        self.last = -1
        attr_value = el.get_attribute("space")
        if attr_value is not None and isinstance(attr_value, str):
            self.space = trans.get_space_by_name(attr_value)
            if self.space is None:
                raise LowlevelError(f"Undefined space: {attr_value}")
        else:
            return

        attr_value = el.get_attribute("first")
        if attr_value is not None and isinstance(attr_value, int):
            self.first = attr_value
        else:
            return

        attr_value = el.get_attribute("last")
        if attr_value is not None and isinstance(attr_value, int):
            self.last = attr_value
        else:
            return

        attr_value = el.get_attribute("name")
        if attr_value is not None and isinstance(attr_value, str):
            point = trans.get_register(attr_value)
            self.space = point.space
            self.first = point.offset
            self.last = (self.first - 1) + point.size
        else:
            return

        if self.space is None:
            raise LowlevelError("No address space indicated in range tag")
```

Note: The Python code does not include the definitions of `AddrSpace`, `Address`, and `LowlevelError` classes as they are specific to Java.