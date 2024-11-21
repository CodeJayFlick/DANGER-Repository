Here is the translation of the given Java code into Python:

```Python
class UnconstrainedEquation:
    def __init__(self, location: str, patex):
        self.patex = patex
        super().__init__(location)

    def dispose(self):
        PatternExpression.release(self.patex)

    def gen_pattern(self, ops):
        self.set_token_pattern(self.patex.gen_min_pattern(ops))

    def resolve_operand_left(self, state):
        state.cur_rightmost = -1
        if self.get_token_pattern().get_left_ellipsis() or self.get_token_pattern().get_right_ellipsis():
            state.size = -1
        else:
            state.size = self.get_token_pattern().get_minimum_length()
        return True


class PatternExpression:
    @classmethod
    def release(cls, patex):
        pass  # Implement this method as needed

    @classmethod
    def gen_min_pattern(cls, ops):
        pass  # Implement this method as needed

    def get_left_ellipsis(self):
        pass  # Implement this method as needed

    def get_right_ellipsis(self):
        pass  # Implement this method as needed

    def get_minimum_length(self):
        pass  # Implement this method as needed


class TokenPattern:
    @classmethod
    def get_token_pattern(cls, patex):
        return None  # Implement this method as needed

    def set_token_pattern(self, pattern):
        pass  # Implement this method as needed

    def get_left_ellipsis(self):
        pass  # Implement this method as needed

    def get_right_ellipsis(self):
        pass  # Implement this method as needed


class VectorSTL:
    @classmethod
    def __init__(self, data=None):
        self.data = data if data is not None else []

    @classmethod
    def append(cls, item):
        cls.data.append(item)

    @classmethod
    def get_data(cls):
        return cls.data

    @classmethod
    def set_data(cls, data):
        cls.data = data


class Location:
    pass  # Implement this class as needed

# Example usage:

location = "some_location"
patex = PatternExpression()
unconstrained_equation = UnconstrainedEquation(location, patex)
ops = VectorSTL()

unconstrained_equation.gen_pattern(ops)

state = {}
unconstrained_equation.resolve_operand_left(state)
```

Please note that this translation is not a direct conversion from Java to Python. Some classes and methods are missing in the original code (like `Location`, `PatternExpression`, etc.), so I've added them here as placeholders for you to implement according to your needs.