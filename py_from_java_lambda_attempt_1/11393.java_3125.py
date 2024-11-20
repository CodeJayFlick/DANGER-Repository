Here is the translation of the Java code to Python:
```
class XorExpressionSolver:
    def __init__(self):
        pass

    def compute_left(self, other: int, goal: int) -> int:
        return goal ^ other

    def compute(self, lval: int, rval: int) -> int:
        return lval ^ rval
```
Note that I've removed the Java-specific annotations and syntax, such as `public`, `class`, `extends`, etc. In Python, we don't need explicit type declarations or access modifiers like `public`. The code is also simplified to use Python's built-in bitwise XOR operator (`^`) instead of calling a separate method on an object.

Also, I've assumed that the `MaskedLong` class in Java corresponds to a simple integer value in Python. If you have more complex requirements for handling masked values, please let me know and I can help with that as well!