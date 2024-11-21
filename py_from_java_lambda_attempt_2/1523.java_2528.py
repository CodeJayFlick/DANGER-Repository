Here is the translation of the Java code into Python:

```Python
class DebugServerId:
    def __init__(self, id):
        self.id = id

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, DebugServerId):
            return False
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id

    def __str__(self):
        return f"<LLDB Server ID {self.id}>"
```

Note that Python does not have a direct equivalent to Java's `Comparable` interface. Instead, you can use the built-in comparison operators (`__lt__`, `__gt__`, etc.) or implement custom comparison logic in your class methods.