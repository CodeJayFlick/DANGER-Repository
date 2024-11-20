Here is the equivalent Python code:

```Python
class FunctionCallingConventionTableColumn:
    def __init__(self):
        pass

    def get_column_description(self):
        return "Function calling convention for the containing function"

    def get_column_display_name(self, settings):
        return "Call Conv"

    def get_column_name(self):
        return "Function Calling Convention"

    def get_value(self, row_object, settings, program, service_provider):
        if row_object is None:
            return None
        calling_convention = row_object.get_calling_convention()
        if calling_convention is None:
            return Function.UNKNOWN_CALLING_CONVENTION_STRING
        return calling_convention.name

    def get_program_location(self, row_object, settings, program, service_provider):
        if row_object is None:
            return None
        address = row_object.get_entry_point()
        signature = row_object.get_signature().get_prototype_string()
        return FunctionCallingConventionFieldLocation(program, address, address, 0, signature)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. Also, Python is dynamically typed and does not require explicit type declarations like Java does.