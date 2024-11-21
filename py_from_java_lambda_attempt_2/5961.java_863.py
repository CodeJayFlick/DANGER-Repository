Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `extends` keyword. Also, Python doesn't support generics like Java does with `<ProgramLocation, String>`. The translation above assumes you are using a class or function to encapsulate the logic and uses type hints for better readability.