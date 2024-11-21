class Constant:
    def __init__(self, v):
        self.val = v

    def long_value(self, buf=None, off=0):
        return self.val

    def length(self, buf=None, off=0):
        return 0


# Example usage:
c = Constant(123)
print(c.long_value())  # prints: 123
