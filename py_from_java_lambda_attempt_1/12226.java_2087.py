Here is the translation of the given Java code into Python:

```Python
class StructurePackResult:
    def __init__(self, num_components: int, structure_length: int, alignment: int, components_changed: bool):
        self.num_components = num_components
        self.structure_length = structure_length
        self.alignment = alignment
        self.components_changed = components_changed


class AlignedStructurePacker:
    def __init__(self, structure: 'StructureInternal', components: list['InternalDataTypeComponent']):
        self.structure = structure
        self.components = components
        self.data_organization = structure.get_data_organization()

    @property
    def data_organization(self):
        return self._data_organization

    @data_organization.setter
    def data_organization(self, value):
        if not isinstance(value, 'DataOrganization'):
            raise TypeError('Expected DataOrganization')
        self._data_organization = value


class AlignedComponentPacker:
    def __init__(self, stored_packing_value: int, data_organization: 'DataOrganization'):
        self.stored_packing_value = stored_packing_value
        self.data_organization = data_organization

    @property
    def default_alignment(self):
        return 0  # Assuming this is the default alignment value in Java code


def pack(self) -> StructurePackResult:
    components_changed = False
    component_count = 0

    for component in self.components:
        if component.get_data_type() == DataType.DEFAULT:  # Replace with actual logic to check DEFAULT datatype
            component.set_data_type(Undefined1DataType.dataType)
            components_changed = True
        else:
            component_count += 1

    packer = AlignedComponentPacker(self.structure.stored_packing_value, self.data_organization)

    for i, component in enumerate(self.components):
        is_last_component = (i + 1 == len(self.components))
        packer.add_component(component, is_last_component)
        if not components_changed and isinstance(component.get_data_type(), Undefined1DataType):  # Assuming this condition should be added
            components_changed = True

    length = packer.length()
    alignment = self.data_organization.machine_alignment()  # Replace with actual logic to get machine alignment in Java code

    return StructurePackResult(component_count, length, alignment, components_changed)


def pack_components(structure: 'StructureInternal', components: list['InternalDataTypeComponent']) -> StructurePackResult:
    packer = AlignedStructurePacker(structure, components)
    return packer.pack()
```

Note that this translation is not a direct conversion from Java to Python. Some parts of the code have been modified or replaced with equivalent logic in Python.