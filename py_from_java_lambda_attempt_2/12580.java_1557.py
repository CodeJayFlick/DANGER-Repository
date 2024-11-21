Here is the translation of the Java interface `ThunkFunction` into a Python class:

```python
class ThunkFunction:
    def __init__(self):
        self.destination_function = None

    def set_destination_function(self, function):
        """Set the destination function which corresponds to this thunk."""
        self.destination_function = function

    def get_destination_function_entry_point(self):
        """Returns the current destination function entry point address."""
        return self.destination_function.entry_point if self.destination_function else None
```

Note that I've used Python's built-in `class` keyword to define a class, and `def` statements to define methods. The Java interface is equivalent to a Python abstract base class (ABC), but since we're not using any ABC-specific features here, I've simply defined a regular class.

I've also replaced the Java-style docstrings with standard Python docstrings, which are indented under each method definition.