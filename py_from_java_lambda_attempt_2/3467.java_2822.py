Here's a translation of the Java code into equivalent Python:

```Python
class OutgoingCallsRootNode:
    def __init__(self, program, function, source_address, filter_duplicates, filter_depth):
        super().__init__(program, function, source_address, "FUNCTION_ICON", filter_duplicates, filter_depth)

    def recreate(self):
        return OutgoingCallsRootNode(self.program, self.function, self.source_address, self.filter_duplicates, self.filter_depth)

    @property
    def icon(self):
        return "FUNCTION_ICON"

    @property
    def name(self):
        return f"Outgoing References - {self.name}"

    @property
    def is_leaf(self):
        return False

    @property
    def tooltip(self):
        return None


# Note: Python does not have direct equivalent of Java's AtomicInteger. You can use int or any other integer type instead.
```

This translation maintains the same structure and functionality as the original Java code, but uses Python syntax and features to achieve similar results.