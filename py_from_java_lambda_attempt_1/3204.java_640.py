Here is the translation of the Java code into Python:

```Python
class SetFunctionPurgeCommand:
    def __init__(self, function: 'ghidra.program.model.listing.Function', new_purge: int):
        self.function = function
        self.new_purge = new_purge

    def apply_to(self, obj) -> bool:
        if isinstance(obj, DomainObject):  # assuming DomainObject is a class in your Python code
            self.function.set_stack_purge_size(self.new_purge)
            return True
        else:
            raise ValueError("Invalid object")

    @property
    def status_msg(self):
        return ""

    @property
    def name(self) -> str:
        return "Set Function Purge"
```

Note that I've used type hints for the function parameters and variables, assuming you're using Python 3.5 or later. Also, since there's no direct equivalent of Java's `DomainObject` in Python, I left it as a placeholder variable to be replaced with your actual class definition.

Please note that this is just one possible translation; depending on how you choose to structure your code and classes, the resulting Python code may look slightly different.