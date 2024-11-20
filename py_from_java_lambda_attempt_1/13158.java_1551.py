Here is the translation of the given Java code into Python:

```Python
class DoubleTests:
    def double2float(self, x):
        return float(x)

    def double2int(self, x):
        return int(x)

    def double2long(self, x):
        return long(x)

    def doubleAdd(self, x, y):
        return x + y

    def doubleComparison1(self, x, y):
        if x < y:
            return 1
        else:
            return 0

    def doubleComparison2(self, x, y):
        if x == y:
            return 1
        else:
            return 0

    def doubleComparison3(self, x, y):
        if x > y:
            return 1
        else:
            return 0

    def return0(self):
        return 0.0

    def return1(self):
        return 1.0

    def divTest(self, x, y):
        if y == 0:
            raise ZeroDivisionError("Cannot divide by zero")
        return x / y

    def mulTest(self, x, y):
        return x * y

    def negTest(self, x):
        return -x

    def remText(self, x, y):
        if y == 0:
            raise ZeroDivisionError("Cannot take modulus of zero")
        return x % y

    def subTest(self, x, y):
        return x - y
```