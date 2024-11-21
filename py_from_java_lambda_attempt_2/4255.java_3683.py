Here is the translation of the Java code to Python:
```
class MemSearchResultToFunctionTableRowMapper:
    def map(self, row_object: 'MemSearchResult', program: object) -> 'function':
        function_manager = program.get_function_manager()
        return function_manager.get_function_containing(row_object.address)
```
Note that I've used type hints to indicate the types of the variables and method parameters. This is not strictly necessary in Python, but it can be helpful for documentation and static analysis purposes.

Also, I've assumed that `get_function_manager()` and `get_function_containing()` are methods on the `program` object, which would need to be implemented elsewhere in your code. Similarly, `MemSearchResult` and `Function` classes would also need to be defined or imported from another module.