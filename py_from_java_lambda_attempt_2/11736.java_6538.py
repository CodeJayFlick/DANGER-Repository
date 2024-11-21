Here is the equivalent Python code:

```Python
class DecisionProperties:
    def __init__(self):
        self.ident_errors = []
        self.conflict_errors = []

    def get_ident_errors(self):
        return self.ident_errors

    def get_conflict_errors(self):
        return self.conflict_errors

    def identical_pattern(self, a, b):
        if not (a.has_error or b.has_error):
            a.set_error(True)
            b.set_error(True)

            msg = f"Constructors with identical patterns:\n  {a}\n  {b}"
            self.ident_errors.append(msg)
            self.conflict_errors.append(msg)

    def conflicting_pattern(self, pa, a, pb, b):
        if not (a.has_error or b.has_error):
            a.set_error(True)
            b.set_error(True)

            msg = f"Constructor patterns cannot be distinguished:\n  {pa}  {a}\n  {pb}  {b}"
            self.conflict_errors.append(msg)
            self.ident_errors.append(msg)
```

Note that Python does not have direct equivalents for Java's `VectorSTL` and `MessageFormattingUtils`. Instead, I used a list (`[]`) to store the error messages. The equivalent of `format()` is f-string formatting in Python.