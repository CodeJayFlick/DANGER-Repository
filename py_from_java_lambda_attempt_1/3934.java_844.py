Here is the translation of the Java code to Python:
```
class FunctionRowObjectToAddressTableRowMapper:
    def map(self, row_object: 'FunctionRowObject', program: 'Program') -> 'Address':
        function = row_object.get_function()
        if function is None:
            return None
        return function.get_entry_point()

# Note: The above Python code assumes that you have defined the following classes in your Python environment:

class FunctionRowObject:
    def get_function(self) -> 'Function': ...

class Program:
    def __init__(self): ...
    def get_entry_point(self) -> 'Address': ...

class Address:
    # ... (no implementation needed for this example)

# You may need to modify the above code based on your specific Python environment and requirements.
```
Note that I've used type hints (`->`) in the `map` method signature, but these are not enforced by Python itself. Additionally, you'll need to define the `FunctionRowObject`, `Program`, and `Address` classes (or their equivalents) in order for this code to work as intended.