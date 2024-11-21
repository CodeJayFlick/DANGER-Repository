Here is the translation of the Java interface `InvalidLink` into a Python class:

```python
class InvalidLink:
    def __init__(self):
        pass

    def __lt__(self, other):
        raise NotImplementedError("compareTo not implemented")

    def __str__(self):
        return ""

    def __hash__(self):
        raise NotImplementedError("hashCode not implemented")

    def __eq__(self, obj):
        if isinstance(obj, InvalidLink):
            return False
        else:
            return NotImplemented

    @property
    def source_file(self):
        pass  # Replace with actual implementation

    @property
    def line_number(self):
        pass  # Replace with actual implementation

    def identity_hash_code(self):
        raise NotImplementedError("identityHashCode not implemented")
```

Note that the `compareTo`, `hashCode`, and `equals` methods are abstract in Python, so we use special methods (`__lt__`, `__hash__`, etc.) to implement their behavior. The other methods (e.g., `source_file`, `line_number`) are simply placeholders for actual implementation.

Also, keep in mind that this is a direct translation of the Java interface into Python code; you may need to modify it further depending on your specific use case and requirements.