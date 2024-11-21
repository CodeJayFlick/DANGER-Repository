Here is the translation of the given Java code into Python:

```Python
class AssemblyEOI:
    EOI = None

    def __init__(self):
        self.EOI = AssemblyEOI()
        super().__init__("$$")

    def __str__(self):
        return "$$"

    def match(self, buffer: str, pos: int, grammar: 'AssemblyGrammar', labels: dict) -> set:
        if pos == len(buffer):
            return {AssemblyParseToken(grammar, self, "")}
        else:
            return set()

    def get_suggestions(self, got: str, labels: dict) -> set:
        return {"$"}
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In this translation, I've kept the same naming conventions as in the original code for better readability.