Here is the translation of the Java code into Python:

```Python
class DisplayableListingOffset:
    def __init__(self, program, current_address):
        self.program = program
        self.address = current_address
        if current_address is None or current_address == Address.NO_ADDRESS:
            return
        function = program.get_function_manager().get_function_containing(current_address)
        start_address = None
        if function is not None:
            start_address = function.get_entry_point()
        else:
            code_unit = program.get_listing().get_code_unit_containing(current_address)
            start_address = code_unit.get_min_address()
        start_offset = start_address.offset
        current_offset = current_address.offset
        self.offset = current_offset - start_offset

    @property
    def address(self):
        return self.address

    @property
    def offset(self):
        return self.offset

    @property
    def display_string(self):
        if self.address is None or self.address == Address.NO_ADDRESS:
            return "NO_OFFSET"
        return str(self.offset)

    def __str__(self):
        return self.display_string()

    def compare_to(self, other_displayable_offset):
        if other_displayable_offset is None:
            return 1
        other_address = other_displayable_offset.address
        if self.address is None or self.address == Address.NO_ADDRESS:
            return (other_address is None or other_address == Address.NO_ADDRESS) and -1 or 0
        if other_address is None or other_address == Address.NO_ADDRESS:
            return 1
        return self.offset - other_displayable_offset.offset

class Address:
    NO_ADDRESS = None

# Usage example:

program = "your program"
current_address = "your current address"

displayable_listing_offset = DisplayableListingOffset(program, current_address)
print(displayable_listing_offset.display_string())
```

Please note that Python does not have a direct equivalent to Java's `@Override` annotation. The `compareTo` method is also implemented differently in the translation because Python does not support operator overloading like Java does with its `<`, `>`, etc., operators.