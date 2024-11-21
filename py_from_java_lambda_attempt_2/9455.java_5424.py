Here is the translation of the Java code into Python:

```Python
class StringBasedFileEditor:
    def set_value(self, value):
        if not isinstance(value, str):
            raise ValueError("Editor only edits string objects!")
        
        super().set_value(value)

    def get_value(self):
        return self.get_as_text()

# Note: This is a simplified translation and does not include the full functionality of the original Java code.
```

This Python class `StringBasedFileEditor` has two methods, `set_value` and `get_value`. The `set_value` method checks if the input value is an instance of string. If it's not, it raises a ValueError with a message indicating that only strings are allowed. Then it calls the superclass's `set_value` method.

The `get_value` method simply returns the result from calling another method (which doesn't exist in this simplified translation), presumably `get_as_text`.