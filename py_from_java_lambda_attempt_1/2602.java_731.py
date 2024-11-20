Here's a translation of the Java interface into Python:

```Python
class TraceSymbol:
    def __init__(self):
        pass

    def get_trace(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_thread(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_parent_namespace(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_parent_symbol(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_references(self, monitor=None):
        if monitor is None:
            return []  # or some default value
        else:
            # implement this method in your subclass
            raise NotImplementedError("Method not implemented")

    def get_reference_collection(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def set_pinned(self, pinned=False):
        pass

    def is_pinned(self):
        return False  # or some default value
```

This Python code defines a class `TraceSymbol` that has the same methods as the Java interface. However, in this implementation, all the methods are abstract and need to be implemented by any subclass of `TraceSymbol`.