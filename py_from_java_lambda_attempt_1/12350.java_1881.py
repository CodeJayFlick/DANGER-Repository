Here is the translation of the given Java code into Python:

```Python
class NoisyStructureBuilder:
    def __init__(self):
        self.offset_to_data_type_map = {}
        self.struct_dt = None
        self.size_of_struct = 0

    def compute_max(self, new_off, length):
        if self.size_of_struct < (new_off + length):
            self.size_of_struct = new_off + length

    def check_for_overlap(self, offset, size):
        for key_value in sorted(self.offset_to_data_type_map.items()):
            last = key_value[0] + key_value[1].get_length()
            if offset < last:
                return key_value
        return None

    @property
    def size(self):
        return self.size_of_struct

    def add_data_type(self, offset, dt):
        if dt is None or isinstance(dt, VoidDataType):
            self.compute_max(offset, 1)
            return
        if isinstance(dt, Pointer):
            base_type = (dt).get_data_type()
            if base_type and base_type == self.struct_dt:
                # Be careful of taking a pointer to the structure when the structure is not fully defined
                dt = manager.get_pointer(DataType.DEFAULT, dt.get_length())
        self.compute_max(offset, dt.get_length())
        first_entry = self.check_for_overlap(offset, dt.get_length())
        if first_entry:
            if first_entry[0] == offset and first_entry[1].get_length() == dt.get_length():
                # Matching field, compare the data-types
                if dt != MetaDataType.get_most_specific_data_type(first_entry[1], dt):
                    return
            elif first_entry[0] <= offset and offset + dt.get_length() < first_entry[0] + first_entry[1].get_length():
                # Completely contained within preexisting entry
                if not isinstance(first_entry[1], Undefined):
                    # Don't override preexisting entry with a smaller one
                    return
            elif isinstance(dt, Undefined):
                # The new field either fully or partially contains preexisting fields
                return
        self.offset_to_data_type_map[first_entry[0]] = dt

    def add_reference(self, offset, dt):
        if dt and isinstance(dt, Pointer):
            dt = (dt).get_data_type()
            if dt and dt == self.struct_dt:
                # Don't allow structure to contain itself
                return
            elif isinstance(dt, Structure) and not dt.get_defined_components():
                self.compute_max(offset, 1)
                return
        else:
            self.compute_max(offset, 1)

    def set_minimum_size(self, size):
        if size > self.size_of_struct:
            self.size_of_struct = size

    @property
    def iterator(self):
        return iter(self.offset_to_data_type_map.items())

    def populate_original_structure(self, dt):
        self.struct_dt = dt
        for component in dt.get_defined_components():
            self.offset_to_data_type_map[component.get_offset()] = component.get_data_type()
        self.size_of_struct = dt.get_length()

class VoidDataType:
    pass

class Pointer:
    def __init__(self, data_type_manager):
        self.data_type_manager = data_type_manager
```

Note: The above Python code does not include the implementation of `VoidDataType`, `Pointer` and other classes which are used in this class. You would need to implement these classes based on your requirements.