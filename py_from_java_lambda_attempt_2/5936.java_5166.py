Here is the translation of the Java code to Python:
```
class IsFunctionVarargsTableColumn:
    def get_column_name(self):
        return "Varargs"

    def get_value(self, row_object: 'ghidra.program.model.listing.Function', settings=None, data=None, service_provider=None) -> bool:
        if not isinstance(row_object, ghidra.program.model.listing.Function):
            raise ValueError("Invalid row object")
        return row_object.has_var_args()
```
Note that I've used type hints to indicate the expected types of the method parameters and return value. This is a Python 3.5+ feature.

Also, since there's no direct equivalent to Java's `extends` keyword in Python, I simply defined a class with methods that match the original code.