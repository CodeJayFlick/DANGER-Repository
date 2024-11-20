class Operator:
    def __init__(self, sign):
        self.sign = sign

    def calculate(self, n1, n2, integer=False):
        if integer:
            return int(n1 + n2) if isinstance(n1, (int, float)) and isinstance(n2, (int, float)) else None
        return round((n1 + n2), 10)

class Plus(Operator):
    def __init__(self):
        super().__init__('+')

    @property
    def calculate(self):
        return lambda n1, n2: self.calculate(n1, n2, integer=True) if isinstance(n1, int) and isinstance(n2, int) else round((n1 + n2), 10)

class Minus(Operator):
    def __init__(self):
        super().__init__('-')

    @property
    def calculate(self):
        return lambda n1, n2: self.calculate(n1, n2, integer=True) if isinstance(n1, int) and isinstance(n2, int) else round((n1 - n2), 10)

class Multiply(Operator):
    def __init__(self):
        super().__init__('*')

    @property
    def calculate(self):
        return lambda n1, n2: self.calculate(n1, n2, integer=True) if isinstance(n1, int) and isinstance(n2, int) else round((n1 * n2), 10)

class Divide(Operator):
    def __init__(self):
        super().__init__('/')

    @property
    def calculate(self):
        return lambda n1, n2: self.calculate(n1, n2, integer=True) if isinstance(n1, int) and isinstance(n2, int) else round((n1 / n2), 10)

class Exponent(Operator):
    def __init__(self):
        super().__init__('^')

    @property
    def calculate(self):
        return lambda n1, n2: self.calculate(n1, n2, integer=True) if isinstance(n1, int) and isinstance(n2, int) else round((n1 ** n2), 10)

# Usage:
plus = Plus()
minus = Minus()
multiply = Multiply()
divide = Divide()
exponent = Exponent()

print(plus.calculate(5.0, 3))  # Output: 8.0
print(minus.calculate(5.0, 3))  # Output: 2.0
print(multiply.calculate(5.0, 3))  # Output: 15.0
print(divide.calculate(10.0, 2))  # Output: 5.0
print(exponent.calculate(2.0, 3))  # Output: 8.0
