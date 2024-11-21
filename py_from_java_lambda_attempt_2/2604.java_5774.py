Here is the translation of the Java interface into a Python class:

```Python
class TraceSymbolNoDuplicatesView:
    def __init__(self):
        pass

    def get_child_named(self, name: str, parent) -> object:
        try:
            for symbol in self.get_children_named(name, parent):
                return symbol
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            return None

    def get_global_named(self, name: str) -> object:
        return self.get_child_named(name, self.get_manager().get_global_namespace())

class LockHold:
    pass  # This is not a real class in Python. It seems to be used for locking purposes.

# Assuming these are actual classes
class TraceSymbolView:
    def __init__(self):
        pass

    def get_children_named(self, name: str, parent) -> list:
        return []

    def get_manager(self) -> object:
        return None  # This should probably be replaced with an instance of a Manager class.

class TraceNamespaceSymbol:
    pass
```

Please note that Python does not have direct equivalent to Java's interface. It has abstract classes or protocols, but they are different from interfaces in terms of their functionality and usage.