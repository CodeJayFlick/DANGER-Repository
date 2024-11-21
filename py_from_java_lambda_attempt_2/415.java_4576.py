Here is the equivalent Python code:

```Python
class DebugSessionId:
    def __init__(self, id):
        self.id = id

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, DebugSessionId):
            return False
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id

    def __str__(self):
        return f"<dbgeng.dll Engine SYSID {self.id}>"
```

Note that Python does not have a direct equivalent to Java's `Comparable` interface. Instead, you can implement the `<` operator (`__lt__`) and use it for comparison if needed.