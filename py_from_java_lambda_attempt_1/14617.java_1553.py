Here is the translation of the Java code to Python:

```Python
class NullNode:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(NullNode, cls).__new__(cls)
        return cls._instance

    def get_tree_size(self):
        return 0

    def get_left(self):
        return None

    def get_right(self):
        return None

    def get_name(self):
        return None

    def walk(self):
        pass
```

Note that Python does not have a direct equivalent to Java's `private static final` fields, so I've used the `_instance` attribute with private access (`_`) instead. The `__new__` method is used to implement the Singleton pattern in Python.