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
