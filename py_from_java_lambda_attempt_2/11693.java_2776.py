Here is the translation of the Java code into Python:

```Python
class EquationOr:
    def __init__(self, location, left, right):
        self.location = location
        self.left = left
        self.right = right

    def dispose(self):
        del self.left
        del self.right

    def gen_pattern(self, ops):
        self.left.gen_pattern(ops)
        self.right.gen_pattern(ops)
        token_pattern = self.left.get_token_pattern().or_(self.right.get_token_pattern())
        # Assuming there's a method to set the token pattern in Python equivalent of getTokenPattern()
        self.set_token_pattern(token_pattern)

    def operand_order(self, ct, order):
        self.left.operand_order(ct, order)
        self.right.operand_order(ct, order)

    def resolve_operand_left(self, state):
        cur_rightmost = -1
        cur_size = -1
        if not self.right.resolve_operand_left(state):
            return False
        if (state.cur_rightmost != -1) and (state.size != -1):
            cur_rightmost = state.cur_rightmost
            cur_size = state.size
        if not self.left.resolve_operand_left(state):
            return False
        if (state.cur_rightmost == -1) or (state.size == -1):
            state.cur_rightmost = cur_rightmost
            state.size = cur_size
        return True

# Assuming the following classes and methods exist in Python:
class Location:
    pass

class PatternEquation:
    def __init__(self, location):
        self.location = location

    def gen_pattern(self, ops):
        # method implementation not provided here

    def get_token_pattern(self):
        # method implementation not provided here

    def or_(self, other):
        # method implementation not provided here
```

Please note that this translation is based on the assumption of Python's syntax and semantics. The actual code may need to be adjusted according to specific requirements.