Here is the translation of the Java code to Python:
```
class AddressTableToAddressTableRowMapper:
    def map(self, row_object: 'ghidra.AddressTable', program: 'ghidra.Program') -> 'ghidra.Address':
        return row_object.get_top_address()
```
Note that I've used type hints for the function parameters and return value to indicate their types. This is not strictly necessary in Python 3.x, but it can be helpful for documentation purposes.

Also note that I haven't included any imports or other boilerplate code, as this translation assumes you already have the relevant modules imported (e.g., `ghidra` module).