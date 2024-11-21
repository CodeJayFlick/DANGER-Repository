Here is the translation of the given Java code into Python:

```Python
class LitAt:
    def __init__(self):
        self.direction = Direction.ZERO
        self.is_directional = True

    @staticmethod
    def register_expression():
        Skript.register_expression(LitAt, Direction, "at")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        return True

    def __str__(self):
        return "at"
```

Note that Python does not have direct equivalents for Java's `@NoDoc` and `@Nullable`, so they are omitted in the translation. Also, Python's type system is more flexible than Java's, so we do not need to specify types explicitly like we would in Java.