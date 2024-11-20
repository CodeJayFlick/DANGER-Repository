Here is the translation of the Java code to Python:
```
class ProgramLocationToSymbolTableRowMapper:
    def map(self, row_object: 'ProgramLocation', program: 'Program') -> 'Symbol':
        symbol_table = program.get_symbol_table()
        return symbol_table.get_primary_symbol(row_object.get_byte_address())
```
Note that I've kept the type hints for clarity and compatibility with Python 3.5+, but if you're using an earlier version of Python, you can remove them.

Also, keep in mind that this is a direct translation from Java to Python, so some things may not be exactly equivalent (e.g., `@Override` annotations are not needed in Python).