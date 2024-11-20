class NumberArithmetic:
    def difference(self, first: float, second: float) -> float:
        return abs(first - second)

    def add(self, value: float, difference: float) -> float:
        return value + difference

    def subtract(self, value: float, difference: float) -> float:
        return value - difference

    def multiply(self, value: float, multiplier: float) -> float:
        return value * multiplier

    def divide(self, value: float, divider: float) -> float:
        if divider == 0:
            raise ZeroDivisionError
        return value / divider

    def power(self, value: float, exponent: float) -> float:
        return pow(value, exponent)
