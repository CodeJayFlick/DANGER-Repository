Here is a translation of the given Java code into equivalent Python:

```Python
class LldbListStackFrameRegistersCommand:
    def __init__(self, manager, bank):
        self.manager = manager
        self.bank = bank
        self.result = {}

    def complete(self, pending):
        return self.result

    def invoke(self):
        self.result = {}
        n = len(self.bank.children)
        for i in range(n):
            child = self.bank.GetChildAtIndex(i, True)
            self.result[DebugClient.getId(child)] = child
```

Note that Python does not have direct equivalents of Java's `HashMap` and `Map`, so we use a regular dictionary (`{}`) instead. Also, the equivalent of Java's `long n = bank.GetNumChildren();` is simply `n = len(self.bank.children)`.

The rest of the code remains largely unchanged, with some minor adjustments to fit Python syntax.