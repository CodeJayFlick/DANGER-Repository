Here is the translation of the Java interface to a Python class:

```python
class FunctionGraphVertexLocationContext:
    def __init__(self):
        pass

    def get_vertex(self) -> 'FGVertex':
        raise NotImplementedError("Must be implemented by subclass")

    def get_vertex_info(self) -> dict:
        return {}
```

Note that I've used the `->` syntax to indicate the type of the method's return value, as is common in Python. However, since Python does not have a built-in equivalent to Java's interface or abstract class, we can't enforce the same level of abstraction and implementation requirements.

In this translation, I've created a simple Python class that defines two methods: `get_vertex` and `get_vertex_info`. The first method is marked as `NotImplementedError`, indicating that it must be implemented by any subclass. The second method returns an empty dictionary (`{}`) for now; you can modify its behavior or return type in your implementation.

Keep in mind that this translation does not preserve the exact semantics of the original Java interface, but rather provides a Python equivalent with similar structure and functionality.