Here's your Java interface translated into a Python class:

```Python
class GEdge:
    def __init__(self):
        pass

    def get_start(self) -> object:
        """Get the start of the edge"""
        raise NotImplementedError("Method not implemented")

    def get_end(self) -> object:
        """Get the end of the edge"""
        raise NotImplementedError("Method not implemented")
```

Note that Python doesn't have a direct equivalent to Java's interfaces. Instead, we can use abstract base classes (ABCs), which are similar but more powerful. However, since you specifically asked for "Python" and only Python, I've used a simple class with methods that raise `NotImplementedError` when called.

Also note that the type hinting (`<V>`) in Java is not directly translatable to Python's syntax. In this case, we're using the built-in `object` as a placeholder for any vertex type.