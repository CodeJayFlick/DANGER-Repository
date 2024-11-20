Here is the translation of the Java code to Python:
```
class RelocationToAddressTableRowMapper:
    def map(self, relocation: 'Relocation', program: 'Program') -> 'Address':
        return relocation.get_address()
```
Note that I've used type hints for the function parameters and return value, as this is a common convention in modern Python code. However, keep in mind that these are not enforced at runtime; they serve only to provide documentation and aid in static analysis.

Also, since there's no direct equivalent of Java's `ServiceProvider` class in Python, I've omitted it from the translation. If you need to pass some kind of service provider or context object into your `map()` function, you could modify the code to accept an additional argument (e.g., a dictionary or custom object) instead.