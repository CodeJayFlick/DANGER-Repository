Here is the translation of the Java code to Python:
```
class FunctionRowObjectToFunctionTableRowMapper:
    def map(self, row_object: 'VTFunctionRowObject', program_data: object, service_provider: object) -> 'Function':
        function_manager = program_data.get_function_manager()
        info = row_object.get_info()
        return function_manager.get_function(info.get_function_id())

# Note: In Python, we don't need to define the class as a subclass of ProgramLocationTableRowMapper
# because it's not necessary. We can simply define a regular class with a map method.
```
Note that I used type hints for the `map` method parameters and return value, but this is optional in Python 3.x.

Also, I didn't translate the Java comments to Python docstrings, as they are not strictly necessary in Python. If you want to add documentation to your code, you can use the triple quotes (`"""`) or the `#` symbol followed by a brief description of what the function does.