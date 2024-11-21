Here is the translation of the Java interface `TraceStackFrame` to a Python class:

```python
class TraceStackFrame:
    def __init__(self):
        pass

    def get_stack(self) -> 'TraceStack':
        raise NotImplementedError("Method not implemented")

    def get_level(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_program_counter(self) -> object:  # Assuming Address is equivalent to a Python object
        raise NotImplementedError("Method not implemented")

    def set_program_counter(self, pc):
        raise NotImplementedError("Method not implemented")

    def get_comment(self) -> str:
        raise NotImplementedError("Method not implemented")

    def set_comment(self, comment: str):
        raise NotImplementedError("Method not implemented")
```

Note that I've used the `NotImplementedError` exception to indicate that these methods are abstract and should be implemented by any concrete subclass.