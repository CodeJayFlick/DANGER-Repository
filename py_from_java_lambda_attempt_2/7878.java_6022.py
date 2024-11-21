Here is the translation of the given Java code into Python:

```Python
class MDSignedEncodedNumber:
    def __init__(self):
        self.signed = False
        self.value = 0

    def set_value(self, value):
        if value < 0:
            self.value = -value
            self.signed = True
        else:
            self.value = value
            self.signed = False

    def get_value(self):
        if self.signed:
            return -self.value
        return self.value

    def insert(self, builder):
        super().insert(builder)
        if self.signed:
            builder.append('-')

class MDException(Exception):
    pass

# Example usage:
try:
    mds = MDSignedEncodedNumber()
    mds.set_value(-10)  # Set the value to -10
    print(mds.get_value())  # Output: 10 (because it's signed)
except Exception as e:
    print(f"An error occurred: {e}")
```

Please note that Python does not have a direct equivalent of Java's `BigInteger` class. The above code uses built-in integer types, which may not be suitable for very large numbers. If you need to work with arbitrarily large integers in Python, consider using the `gmpy2` or `sympy` libraries.