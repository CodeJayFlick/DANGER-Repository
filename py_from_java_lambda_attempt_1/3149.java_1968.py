Here is the translation of the given Java code into Python:

```Python
class CreateArrayInStructureCmd:
    def __init__(self, addr, num_elements, data_type, comp_path):
        self.addr = addr
        self.num_elements = num_elements
        self.data_type = data_type
        self.comp_path = comp_path

    def apply_to(self, obj):
        program = Program(obj)
        listing = program.get_listing()

        data = listing.get_data_containing(addr)
        if not data:
            return False

        comp_data = data.get_component(comp_path)
        if not comp_data:
            print("Invalid target component path specified")
            return False

        index = comp_data.get_component_index()
        offset = comp_data.get_parent_offset()
        parent_data_type = comp_data.get_parent().get_base_data_type()

        if not isinstance(parent_data_type, Structure):
            print("Data not in a structure")
            return False

        struct = parent_data_type
        base_dt = self.data_type
        if isinstance(self.data_type, TypeDef):
            base_dt = self.data_type.get_base_data_type()
        elif isinstance(base_dt, Dynamic):
            print(f"Dynamic data-type may not be specified: {self.data_type.name}")
            return False

        try:
            array_dt = ArrayDataType(self.data_type, num_elements)
            length = 0 if array_dt.is_zero_length() else array_dt.get_length()

            if struct.is_packing_enabled and offset + length > struct.get_length():
                print("Array too big for structure")
                return False
            self.clear_struct(struct, comp_data.get_parent_offset(), length)

            if not struct.is_packing_enabled:
                struct.insert(index, array_dt)
            else:
                struct.replace(index, array_dt)

        except Exception as e:
            print(f"Unexpected error: {e}")
            return False

        return True

    def clear_struct(self, struct, offset, length):
        comps = struct.get_defined_components()
        end_offset = offset + length
        for i in range(len(comps) - 1, -1, -1):
            if comps[i].get_offset() >= offset and comps[i].get_offset() < end_offset:
                struct.clear_component(comps[i].get_ordinal())
        return

    def get_status_msg(self):
        return self.msg

    def get_name(self):
        return "Create Array"
```

Note: This Python code does not include the necessary imports or classes that are required for this script to run. It is assumed that you have already defined these in your own code, and only need a translation of the given Java code into Python.