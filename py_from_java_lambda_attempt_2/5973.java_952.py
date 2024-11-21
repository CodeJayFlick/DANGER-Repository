Here is the translation of the Java code to Python:
```
class AddressToFunctionContainingTableRowMapper:
    def map(self, row_object: 'Address', program: object) -> 'Function':
        function_manager = program.get_function_manager()
        return function_manager.get_function_containing(row_object)

if __name__ == '__main__':
    pass
```
Note that I've kept the type hints for `row_object` and `program`, as they are useful in Python to indicate the expected types of variables. However, if you're not using a static analyzer or IDE with type checking, these can be removed.

Also, since there is no equivalent concept to Java's `ServiceProvider` in Python, I've simply omitted it from the translation. If you need to pass additional data or services to the `map` method, you would typically use keyword arguments (e.g., `def map(self, row_object: 'Address', program: object, service_provider: object) -> 'Function':`)