Here is the translation of the Java interface `ch.njol.yggdrasil.FieldHandler` to a Python class:

```python
class FieldHandler:
    def excessive_field(self, o: object, field_context: dict) -> bool:
        """Called when a loaded field doesn't exist."""
        # Your implementation here
        pass

    def missing_field(self, o: object, field: str) -> bool:
        """Called if a field was not found in the stream."""
        # Your implementation here
        pass

    def incompatible_field(self, o: object, f: dict, field_context: dict) -> bool:
        """Called when a loaded value is not compatible with the type of a field."""
        # Your implementation here
        pass
```

Note that I've used Python's built-in `object` and `dict` types to represent Java's `Object` and `Field`, respectively. Additionally, I've replaced Java's `throws StreamCorruptedException` clause with an empty `pass` statement in each method, as this is equivalent to a no-op in Python.

You'll need to implement the logic for these methods according to your specific requirements.