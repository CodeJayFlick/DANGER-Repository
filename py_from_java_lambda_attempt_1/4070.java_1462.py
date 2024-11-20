Here is the translation of the Java code to Python:
```
class LocationReferenceToFunctionContainingTableRowMapper:
    def map(self, row_object: 'LocationReference', program: object, service_provider: object) -> object:
        location_of_use = row_object.get_location_of_use()
        function_manager = program.get_function_manager()
        return function_manager.get_function_containing(location_of_use)
```
Note that I've used Python's type hints to indicate the types of the method parameters and return value. This is not strictly necessary, but it can be helpful for documentation purposes.

Also, note that in Python, we don't need an `extends` clause like Java does when defining a subclass. Instead, we simply define the class with its own attributes and methods.

Finally, I've used the `object` type to represent the return value of the `map` method, since it's not clear from the original code what specific type should be returned (e.g., `Function`). If you know that the return value should be a specific Python object or class, feel free to modify this accordingly.