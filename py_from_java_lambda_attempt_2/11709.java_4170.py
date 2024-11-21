Here is the translation of the given Java code into Python:

```Python
class PatternEquation:
    def __init__(self, location):
        self.location = location
        self.resultpattern = TokenPattern(location)
        self.refcount = 0

    @property
    def token_pattern(self):
        return self.resultpattern

    def set_token_pattern(self, token_pattern):
        self.resultpattern = TokenPattern(self.location, token_pattern)

    def dispose(self):
        # Only delete through release
        pass

    def gen_pattern(self, ops):
        raise NotImplementedError("Must be implemented by subclass")

    def resolve_operand_left(self, state):
        raise NotImplementedError("Must be implemented by subclass")

    def operand_order(self, ct, order):
        # By default do nothing
        pass

    def lay_claim(self):
        self.refcount += 1

    @classmethod
    def release(cls, pateq):
        pateq.refcount -= 1
        if pateq.refcount <= 0:
            pateq.dispose()


class TokenPattern:
    def __init__(self, location, token_pattern=None):
        self.location = location
        self.token_pattern = token_pattern


# Note: The following classes are not defined in the given Java code.
#       They were imported from other packages and may have different implementations.

class VectorSTL(list): pass

class Location: pass

class Constructor: pass

class OperandSymbol: pass
```

This Python translation maintains the same structure as the original Java code, with some minor adjustments to accommodate differences between the two languages.