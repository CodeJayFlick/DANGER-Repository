Here is the translation of the Java code to Python:
```
class ResourceFieldLocation:
    def __init__(self, program, address, component_path, display_value, op_index, character_offset, data):
        super().__init__(program, address, component_path, None, display_value, op_index, character_offset)
        self.data = data

    @classmethod
    def from_xml(cls):  # Default constructor needed for restoring from XML.
        pass

    def get_resource_data(self):
        if not hasattr(self, 'data') or self.data is None:
            self.data = DataUtilities.get_data_at_location(self)
        return self.data

    def is_data_image_resource(self):
        self.get_resource_data()  # side effect to init data if null after deserialization
        return isinstance(self.data.value, DataImage) if hasattr(self, 'data') and self.data else False


class ProgramLocation:
    pass


class OperandFieldLocation(ProgramLocation):  # Note: This is not a direct translation of the Java class.
    def __init__(self, program, address, component_path, display_value, op_index, character_offset):
        super().__init__()
        self.program = program
        self.address = address
        self.component_path = component_path
        self.display_value = display_value
        self.op_index = op_index
        self.character_offset = character_offset

    def __str__(self):
        return f"ProgramLocation(program={self.program}, address={self.address}, component_path={self.component_path}, " \
               f"display_value={self.display_value}, op_index={self.op_index}, character_offset={self.character_offset})"


class Data:
    pass


class DataImage:
    pass


def get_data_at_location(location):
    # This is a placeholder for the Java method. You would need to implement this in Python.
    return None
```
Note that I did not translate the `Program`, `Address`, and other classes, as they are specific to the Ghidra framework and may require additional context or implementation details to accurately translate them to Python.

Also, some methods like `DataUtilities.get_data_at_location` is a placeholder for Java method. You would need to implement this in Python.

This code should give you an idea of how the original Java code could be translated to Python. However, please note that it may not work as-is and might require additional modifications or implementation details specific to your use case.