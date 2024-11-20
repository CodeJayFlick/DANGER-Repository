Here is the translation of the given Java code into equivalent Python:

```Python
class MDManagedPropertyParser:
    def __init__(self):
        pass

    @staticmethod
    def parse(modifier_type_name: str, dmang) -> 'MDManagedProperty':
        if not isinstance(dmang, dict):  # Assuming dmang is a dictionary in the Python version.
            raise ValueError("dmang must be a dictionary")

        managed_property = None
        iter = CharacterIteratorAndBuilder(dmang)

        while True:
            char = iter.peek()
            if char == '$':
                iter.get_and_increment()  # Consume the $
                next_char = iter.peek()

                if next_char in ['A', 'B', 'C']:
                    managed_property_type = {
                        'A': MDGCProperty,
                        'B': MDPinPointerProperty,
                        'C': MDCLIProperty
                    }[next_char]
                    managed_property = managed_property_type(modifier_type_name, dmang)
                elif next_char.isdigit():
                    managed_property = MDCLIArrayProperty(modifier_type_name, dmang)
                else:
                    break  # Unknown character. Stop parsing.
            else:
                break  # Not a modifier type name. Stop parsing.

        return managed_property


class CharacterIteratorAndBuilder:
    def __init__(self, dmang):
        self.dmang = dmang
        self.index = 0

    def peek(self) -> str:
        if self.index >= len(self.dmang['mangled_string']):
            raise ValueError("End of string reached")
        return self.dmang['mangled_string'][self.index]

    def get_and_increment(self):
        result = self.peek()
        self.index += 1
        return result


class MDManagedProperty:
    pass


class MDGCProperty(MDManagedProperty):
    def __init__(self, modifier_type_name: str, dmang):
        super().__init__()
        # Add any necessary attributes or methods here.


class MDPinPointerProperty(MDManagedProperty):
    def __init__(self, modifier_type_name: str, dmang):
        super().__init__()
        # Add any necessary attributes or methods here.


class MDCLIProperty(MDManagedProperty):
    def __init__(self, modifier_type_name: str, dmang):
        super().__init__()
        # Add any necessary attributes or methods here.


class MDCLIArrayProperty(MDManagedProperty):
    def __init__(self, modifier_type_name: str, dmang):
        super().__init__()
        # Add any necessary attributes or methods here.
```

Please note that the Python code does not have direct equivalent of Java's switch statement. Instead, we use if-elif ladder to achieve similar functionality.