class SourceTypeTableColumn:
    def get_column_name(self):
        return "Symbol Source"

    def get_value(self, row_object: 'ProgramLocation', settings=None, program='None', service_provider=None) -> str | None:
        symbol_table = program.get_symbol_table()
        primary_symbol = symbol_table.get_primary_symbol(row_object.address)
        
        if primary_symbol is not None:
            return str(primary_symbol.source)
        else:
            return None
