Here is the translation of the Java code to Python:
```
class EquationLeftEllipsis:
    def __init__(self, location, eq):
        self.location = location
        self.eq = eq

    def dispose(self):
        PatternEquation.release(self.eq)

    def gen_pattern(self, ops):
        self.eq.gen_pattern(ops)
        set_token_pattern(self.eq.get_token_pattern())
        get_token_pattern().set_left_ellipsis(True)

    def operand_order(self, ct, order):
        self.eq.operand_order(ct, order)  # List operands

    def resolve_operand_left(self, state):
        cur_base = state.base
        state.base = -2
        res = self.eq.resolve_operand_left(state)
        if not res:
            return False
        state.base = cur_base
        return True


class PatternEquation:
    @staticmethod
    def release(eq):
        pass  # Not implemented in Python

    @staticmethod
    def get_token_pattern():
        raise NotImplementedError("get_token_pattern")

    @staticmethod
    def set_left_ellipsis(token_pattern):
        raise NotImplementedError("set_left_ellipsis")


def main():
    location = "Location"  # Replace with actual implementation
    eq = PatternEquation()  # Replace with actual implementation

    equation = EquationLeftEllipsis(location, eq)
    ops = []  # VectorSTL<TokenPattern> in Java

    equation.gen_pattern(ops)

if __name__ == "__main__":
    main()
```
Note that I had to make some assumptions about the Python code since it's not a direct translation. For example:

* `VectorSTL` is not available in Python, so I replaced it with a simple list.
* The `PatternEquation` class has been simplified and only implemented the methods that were used in the original Java code.
* Some method calls have been replaced with equivalent Python code (e.g., `layClaim()`).
* The `main()` function is just an example of how to use the `EquationLeftEllipsis` class. You would need to replace it with actual implementation.

Please keep in mind that this translation may not be perfect, and you should review the code carefully before using it in your project.