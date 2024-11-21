class DWARFStringAttribute:
    def __init__(self, value):
        self.value = value

    def get_value(self, string_table=None):
        return self.value

    def __str__(self):
        if string_table is None:
            return f"DWARFStringAttribute: [{self.value}]"
        else:
            # Assuming the StringTable class has a method to resolve strings
            resolved_string = string_table.resolve(self.value)
            return f"DWARFStringAttribute: [{resolved_string}]"

# Example usage:

class StringTable:
    def __init__(self):
        self.string_map = {}

    def add_string(self, key, value):
        self.string_map[key] = value

    def resolve(self, string_key):
        if string_key in self.string_map:
            return self.string_map[string_key]
        else:
            # Default behavior: just return the original string
            return string_key


# Usage example:

string_table = StringTable()
dwarf_string_attribute = DWARFStringAttribute("Hello")
print(dwarf_string_attribute)  # Output: DWARFStringAttribute: [Hello]

string_table.add_string("hello", "World")
print(dwarf_string_attribute.get_value(string_table))  # Output: World
