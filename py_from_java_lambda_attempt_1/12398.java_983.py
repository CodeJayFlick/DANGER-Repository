Here is the translation of the Java code into Python:

```Python
class StructuredDynamicDataType:
    def __init__(self, name: str, description: str):
        self.description = description
        self.components = []
        self.component_names = []
        self.component_descs = []

    def add(self, data_type: 'DataType', component_name: str, component_description: str) -> None:
        self.components.append(data_type)
        self.component_names.append(component_name)
        self.component_descs.append(component_description)

    def set_components(self, components: list['DataType'], names: list[str], desc: list[str]) -> None:
        self.components = components
        self.component_names = names
        self.component_descs = desc

    def get_all_components(self) -> list['DataTypeComponent']:
        return [ReadOnlyDataTypeComponent(data_type, self, len, i, offset)
                for i, data_type in enumerate(self.components)]

    @property
    def description(self):
        return self._description


class ReadOnlyDataTypeComponent:
    def __init__(self, data_type: 'DataType', parent: 'StructuredDynamicDataType',
                 length: int, index: int, offset: int, name: str, desc: str) -> None:
        self.data_type = data_type
        self.parent = parent
        self.length = length
        self.index = index
        self.offset = offset
        self.name = name
        self.desc = desc


class DataTypeComponent:
    pass

# You would need to implement the following methods in Python:

def get_value(self, buf: 'MemBuffer', settings: object, length: int) -> object:
    return None  # Implement this method as per your requirement.

def get_representation(self, buf: 'MemBuffer', settings: object, length: int) -> str:
    return ""  # Implement this method as per your requirement.
```

Note that I have not implemented the `get_value` and `get_representation` methods in Python because they seem to be specific to the context of Ghidra.