Here is the translation of the Java code to Python:
```
class FunctionRowObjectToFunctionTableRowMapper:
    def map(self, row_object: 'FunctionRowObject', program: 'Program') -> 'Function':
        function = row_object.get_function()
        return function
```
Note that I've used type hints in the Python version, which are not present in the original Java code. These type hints provide information about the expected types of the arguments and the return value, but they do not affect the runtime behavior of the code.

Also, since there is no direct equivalent to Java's `extends` keyword in Python, I've simply defined a class with the same name as the original Java class.