Here is the translation of the given Java code into Python:

```Python
class AddStackRefCmd:
    def __init__(self, from_addr, op_index, stack_offset, source):
        self.from_addr = from_addr
        self.op_index = op_index
        self.stack_offset = stack_offset
        self.source = source

    def apply_to(self, obj):
        p = obj  # Assuming 'obj' is a Program object in Python
        f = p.get_function_containing(self.from_addr)
        
        if f is None:
            return False
        
        if not hasattr(self, 'ref_type'):
            self.ref_type = get_default_stack_ref_type(p.listing.code_unit_at(self.from_addr), self.op_index)

        var = f.stack_frame.get_variable_containing(self.stack_offset)
        if var is None:
            try:
                f.stack_frame.create_variable(None, self.stack_offset, None, source=SourceType.DEFAULT)
            except (DuplicateNameException, InvalidInputException, AddressOutOfBoundsException) as e:
                return False
        
        p.reference_manager.add_stack_reference(self.from_addr, self.op_index, self.stack_offset, self.ref_type, self.source)
        return True

    def get_status_msg(self):
        return getattr(self, 'status', '')

    def get_name(self):
        return "Add Stack Reference"


class SourceType:
    DEFAULT = 0


def get_default_stack_ref_type(code_unit, op_index):
    # This function should be implemented based on the actual logic in Java's RefTypeFactory.getDefaultStackRefType()
    pass
```

Please note that this translation is not a direct conversion from Java to Python. It requires some understanding of both languages and their respective syntaxes. Also, I've assumed 'obj' as a Program object in Python, which might need further modification based on the actual usage.