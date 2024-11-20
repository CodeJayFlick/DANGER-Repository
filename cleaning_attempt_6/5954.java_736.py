class ReferenceFromLabelTableColumn:
    def get_column_display_name(self):
        return self.get_column_name()

    def get_column_name(self):
        return "Label"

    def get_value(self, row_object: 'ReferenceAddressPair', settings=None, program=None) -> str | None:
        symbol = self._get_symbol(row_object=row_object, program=program)
        if symbol is not None:
            return symbol.name
        return None

    def _get_symbol(self, row_object: 'ReferenceAddressPair', program: 'Program') -> 'Symbol' | None:
        from_address = row_object.source
        symbol_table = program.symbol_table
        primary_symbol = symbol_table.get_primary_symbol(from_address)
        if primary_symbol is not None:
            return primary_symbol

    def get_program_location(self, row_object: 'ReferenceAddressPair', settings=None, program=None) -> 'ProgramLocation' | None:
        symbol = self._get_symbol(row_object=row_object, program=program)
        if symbol is not None:
            return symbol.program_location
        return None


class ReferenceAddressPair:
    def __init__(self):
        pass

    @property
    def source(self) -> 'Address':
        raise NotImplementedError("source property must be implemented")

class ProgramLocation:
    def __init__(self):
        pass

class SymbolTable:
    def get_primary_symbol(self, from_address: 'Address') -> 'Symbol' | None:
        raise NotImplementedError("get_primary_symbol method must be implemented")


class Address:
    @property
    def source(self) -> str:
        raise NotImplementedError("source property must be implemented")

class Program:
    @property
    def symbol_table(self) -> 'SymbolTable':
        raise NotImplementedError("symbol_table property must be implemented")
