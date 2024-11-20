class ProgramLocationToSymbolTableRowMapper:
    def map(self, row_object: 'ProgramLocation', program: 'Program') -> 'Symbol':
        symbol_table = program.get_symbol_table()
        return symbol_table.get_primary_symbol(row_object.get_byte_address())
