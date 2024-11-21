Here is the translation of the given Java code into Python:

```Python
class SetFunctionVarArgsCommand:
    def __init__(self, function: 'ghidra.program.model.listing.Function', has_var_args: bool):
        self.function = function
        self.has_var_args = has_var_args

    def apply_to(self, obj) -> bool:
        if isinstance(obj, DomainObject):  # Assuming DomainObject is a class in Python
            self.function.set_var_args(self.has_var_args)
            return True
        else:
            raise ValueError("Invalid object type")

    @property
    def status_msg(self):
        return ""

    @property
    def name(self) -> str:
        return "Set Function VarArgs"
```

Note that I've used Python's built-in support for classes, methods and properties. Also note that the `DomainObject` class is not defined in this code snippet as it was assumed to be a part of some larger framework or library.