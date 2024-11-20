Here is the translation of the Java code to Python:
```python
class StackVariableComparator:
    _instance = None

    def compare(self, obj1: object, obj2: object) -> int:
        offset1 = self.get_stack_offset(obj1)
        offset2 = self.get_stack_offset(obj2)

        if offset1 is None and offset2 is None:
            return 0
        elif offset1 is None:
            return -1
        elif offset2 is None:
            return 1

        if offset1 < offset2:
            return -1
        elif offset2 < offset1:
            return 1
        else:
            return 0

    def get_stack_offset(self, obj: object) -> int | None:
        if isinstance(obj, Variable):
            var = obj
            if var.has_stack_storage():
                return int(var.get_last_storage_varnode().get_address().get_offset())
            return None
        elif isinstance(obj, int):
            return obj
        else:
            raise ValueError(f"{obj.__class__.__name__} is unsupported type")

    @classmethod
    def get(cls) -> 'StackVariableComparator':
        if cls._instance is None:
            cls._instance = StackVariableComparator()
        return cls._instance

# Note: The Variable class and its methods are not defined in this code,
# so you would need to define them separately or use a different approach.
```
Note that I've used type hints for the `compare` method, but Python 3.9+ is required for these to be enforced at runtime. In earlier versions of Python, you can remove the type hints if needed.

Also, as mentioned in the comment, the `Variable` class and its methods are not defined in this code, so you would need to define them separately or use a different approach.