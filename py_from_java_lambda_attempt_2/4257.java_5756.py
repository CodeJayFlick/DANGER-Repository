Here's a translation of your Java code into equivalent Python:

```Python
class MemSearchTableModel:
    def __init__(self, serviceProvider, selection_size, program, search_info, start_address, program_selection):
        self.search_info = search_info
        self.start_address = start_address
        self.program_selection = program_selection

        super().__init__("Memory Search", serviceProvider, program)

        self.selection_size = selection_size

    def do_load(self, accumulator, monitor):
        algorithm = self.search_info.create_search_algorithm(self.get_program(), self.start_address, self.program_selection)
        algorithm.search(accumulator, monitor)

    def get_program_location(self, row, column):
        if not hasattr(self, 'program'):
            return None  # we've been disposed

        program = self.get_program()
        location = super().get_program_location(row, column)
        if location and program.memory.contains(location.byte_address):
            return BytesFieldLocation(program, location.byte_address)

    def get_address(self, row):
        result = self.get_row_object(row)
        return result.address

    def get_program_selection(self, rows):
        if self.selection_size == 1:
            return super().get_program_selection(rows)

        add_on = self.selection_size - 1
        address_set = set()
        for element in rows:
            min_addr = self.get_address(element)
            max_addr = min_addr
            try:
                max_addr += add_on
                address_set.add((min_addr, max_addr))
            except Exception as e:
                pass

        return ProgramSelection(address_set)

class BytesFieldLocation:
    def __init__(self, program, byte_address):
        self.program = program
        self.byte_address = byte_address

class AddressSet(set):
    pass

class ProgramSelection:
    def __init__(self, address_set):
        self.address_set = address_set
```

Please note that Python does not have direct equivalent of Java's generics. So I removed the type parameter from `MemSearchTableModel` and other classes as they are not necessary in Python.

Also, Python doesn't support unchecked exceptions like Java. If you want to catch all types of exceptions, use a bare except block or specify specific exception types that your code can handle.