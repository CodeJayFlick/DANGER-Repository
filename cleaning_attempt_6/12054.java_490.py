class StackReferenceDB:
    def __init__(self, program, from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id):
        pass  # Note: In Python, we don't need explicit constructors like in Java.

    def get_stack_offset(self):
        return int(to_addr.get_offset())

    def is_stack_reference(self):
        return True
