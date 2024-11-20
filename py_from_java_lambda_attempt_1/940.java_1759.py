Here is the translation of the given Java interface into a Python class:

```Python
class DebugHostSymbol2:
    def enumerate_children_ex(self, kind: int, name: str, search_info) -> 'DebugHostSymbolEnumerator':
        pass  # implement this method in your subclass

    def get_language(self) -> int:
        pass  # implement this method in your subclass


class DebugHostSymbolEnumerator:
    pass
```

Please note that the Java interface is abstract and cannot be instantiated. Similarly, we have created an abstract class `DebugHostSymbol2` with two methods: `enumerate_children_ex` and `get_language`. These methods are placeholders for actual implementation.

The Python code does not include any equivalent of Java's `ByReference`, as it is a JNA-specific feature that allows passing complex objects by reference. In Python, you would typically pass these types of objects directly or use some other mechanism to handle the object lifetime and memory management.