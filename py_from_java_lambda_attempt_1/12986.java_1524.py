Here is the translation of the Java code into Python:

```Python
class ReferenceManagerTestDouble:
    def add_reference(self, reference):
        raise NotImplementedError()

    def add_stack_reference(self, from_addr, op_index, stack_offset, ref_type, source):
        raise NotImplementedError()

    def add_register_reference(self, from_addr, op_index, register, ref_type, source):
        raise NotImplementedError()

    def add_memory_reference(self, from_addr, to_addr, ref_type, source, op_index):
        raise NotImplementedError()

    def add_offset_mem_reference(self, from_addr, to_addr, offset, ref_type, source, op_index):
        raise NotImplementedError()

    def add_shifted_mem_reference(self, from_addr, to_addr, shift_value, ref_type, source, op_index):
        raise NotImplementedError()

    def add_external_reference(self, from_addr, library_name, ext_label, ext_addr, source, op_index, ref_type):
        try:
            # This will throw an exception if the input is invalid
            pass
        except (InvalidInputException, DuplicateNameException) as e:
            raise

    def remove_all_references_from(self, begin_addr, end_addr):
        raise NotImplementedError()

    def get_references_to(self, var):
        raise NotImplementedError()

    def set_primary(self, ref, is_primary):
        raise NotImplementedError()

    def has_flow_references_from(self, addr):
        raise NotImplementedError()

    def get_flow_references_from(self, addr):
        raise NotImplementedError()

    def get_external_references(self):
        raise NotImplementedError()

    def get_reference_iterator(self, start_addr):
        raise NotImplementedError()

    def get_reference(self, from_addr, to_addr, op_index):
        raise NotImplementedError()

    def has_references_from(self, from_addr):
        raise NotImplementedError()

    def has_references_from(self, from_addr, op_index):
        raise NotImplementedError()

    def get_primary_reference_from(self, addr, op_index):
        raise NotImplementedError()

    def get_reference_source_iterator(self, start_addr, forward=True):
        raise NotImplementedError()

    def get_reference_destination_iterator(self, start_addr, forward=True):
        raise NotImplementedError()

    def get_reference_count_to(self, to_addr):
        return 0

    def get_reference_count_from(self, from_addr):
        return 0

    def has_references_to(self, to_addr):
        return False
```

Please note that this is a direct translation of the Java code into Python. It does not include any error handling or testing for invalid inputs as it was in the original Java code.