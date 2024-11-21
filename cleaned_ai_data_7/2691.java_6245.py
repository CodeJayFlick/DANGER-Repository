class DefaultEnumeratedColumnProgramTableModel:
    def __init__(self, name: str, col_type: type, sel_column):
        self.name = name
        self.col_type = col_type
        self.sel_column = sel_column

    @property
    def program(self) -> 'Program':
        return self._program

    @program.setter
    def program(self, value: 'Program'):
        self._program = value

    def get_program_location(self, row: int, column: int):
        if not isinstance(get_column_class(column), (Address, ProgramLocation)):
            return None
        value = self.get_value_at(row, column)
        if isinstance(value, Address):
            return ProgramLocation(self.program, value)
        elif isinstance(value, ProgramLocation):
            return value
        else:
            raise AssertionError()

    def get_program_selection(self, rows: list) -> 'ProgramSelection':
        if not self.sel_column:
            return None
        sel = set()
        for r in rows:
            value = self.get_value_of_row_object(r)
            if isinstance(value, Address):
                sel.add(value)
            elif isinstance(value, AddressRange):
                sel.add(value)
            elif isinstance(value, AddressSetView):
                sel.add(value)
            else:
                raise AssertionError()
        return ProgramSelection(sel)

    def get_column_class(self, column: int) -> type:
        # implement this method
        pass

    def get_value_at(self, row: int, column: int) -> object:
        # implement this method
        pass

    def get_row_object(self, row: int) -> object:
        # implement this method
        pass


class ProgramLocation:
    def __init__(self, program: 'Program', address):
        self.program = program
        self.address = address


class AddressSetView:
    pass


class AddressRange:
    pass


class Address:
    pass


class ProgramSelection:
    def __init__(self, addresses_set):
        self.addresses_set = addresses_set

