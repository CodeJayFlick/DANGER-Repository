Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's generics, so I used type hints to indicate the expected types. Also, Python does not support method overriding like Java does with its `@Override` annotation.