class DBTraceProgramViewRegisterListing:
    def __init__(self, program, reg_space):
        self.thread = reg_space.get_thread()
        self.min_addr = None  # Assuming these are not used anywhere else in the class.
        self.max_addr = None

    def get_thread(self):
        return self.thread

    def do_create_undefined_unit(self, address):
        raise UnsupportedOperationException()

    def is_undefined(self, start, end):
        if code_operations.undefined_data().covers_range(program.snap, AddressRangeImpl(start, end)):
            return True
        else:
            return False

    def clear_code_units(self, start_addr, end_addr, clear_context=False, monitor=None):
        try:
            code_operations.defined_units().clear(AddressRangeImpl(start_addr, end_addr), clear_context, monitor)
        except CancelledException as e:
            raise AssertionError(e)

    # TODO: Delete this when the interface removes it
    def clear_all(self, clear_context=False, monitor=None):
        try:
            code_operations.defined_units().clear(min_addr=max_addr, clear_context=clear_context, monitor=monitor)
        except CancelledException as e:
            raise AssertionError(e)


class AddressRangeImpl:
    def __init__(self, start, end):
        self.start = start
        self.end = end

# Assuming these are not used anywhere else in the class.
code_operations = None  # Code operations object
program = None  # Program object
