Here is the translation of the Java code to Python:
```
class SymbolToAddressTableRowMapper:
    def map(self, symbol: 'Symbol', program: 'Program') -> 'Address':
        return symbol.get_address()
```
Note that I've used type hints for the function parameters and return value, but this is not strictly necessary in Python. The code can be written without type hints as well.

Here's a breakdown of how each line was translated:

* `public class SymbolToAddressTableRowMapper extends ProgramLocationTableRowMapper<Symbol, Address>` becomes simply `class SymbolToAddressTableRowMapper:`
* `@Override` is not needed in Python, so it was removed.
* The method signature remains the same, with the addition of type hints for the function parameters and return value.