Here is the translation of the Java code into Python:

```Python
class AvailableRegisterRow:
    def __init__(self, number: int, register):
        self.number = number
        self.register = register
        self.contains = compute_contains()

    @property
    def contains(self) -> str:
        return self._contains

    @contains.setter
    def contains(self, value: str):
        self._contains = value

    def compute_contains(self) -> str:
        descendants = set()
        collect_children(self.register, descendants)
        return ', '.join(descendants)

    def collect_children(self, reg, descendants):
        for child in reg.get_child_registers():
            descendants.add(child.name())
            self.collect_children(child, descendants)

    @property
    def register(self) -> object:
        return self._register

    @register.setter
    def register(self, value: object):
        self._register = value

    @property
    def number(self) -> int:
        return self._number

    @number.setter
    def number(self, value: int):
        self._number = value

    def get_register(self) -> object:
        return self.register

    def get_number(self) -> int:
        return self.number

    def get_name(self) -> str:
        return self.register.name()

    def get_bits(self) -> int:
        return self.register.get_bit_length()

    def get_group(self) -> str:
        group = self.register.group()
        if group is None:
            return '(none)'
        return group

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, value: bool):
        self._selected = value

    def is_selected(self) -> bool:
        return self.selected

    @property
    def known(self):
        return self._known

    @known.setter
    def known(self, value: bool):
        self._known = value

    def is_known(self) -> bool:
        return self.known

    def set_known(self, value: bool):
        self.known = value

    def get_parent_name(self) -> str:
        base = self.register.get_base_register()
        if base == self.register or base is None:
            return ''
        return base.name()

class Register:
    pass
```

Note that I did not implement the `Register` class as it was not provided in the original Java code. You would need to define this class based on your specific requirements.