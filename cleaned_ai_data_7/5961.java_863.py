class SymbolTypeTableColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Symbol Type"

    def get_value(self, row_object: 'ProgramLocation', settings=None, program='None', service_provider=None) -> str | None:
        if isinstance(row_object, VariableLocation):
            var_loc = row_object
            return f"Parameter" if var_loc.is_parameter else "Local Var"
        
        symbol_table = program.get_symbol_table()
        symbol = None
        
        if isinstance(row_object, LabelFieldLocation):
            lab_loc = row_object
            symbol = lab_loc.get_symbol()
        else:
            symbol = symbol_table.get_primary_symbol(row_object.get_address())
        
        if symbol is None:
            return None

        return SymbolUtilities.get_symbol_type_display_name(symbol)
