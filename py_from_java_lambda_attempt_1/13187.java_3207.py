Here is the translation of the given Java code into Python:

```Python
class RecursionTest:
    def triangular_numbers_int(self, n):
        if n <= 0:
            return 0
        return n + self.triangular_numbers_int(n-1)

    def triangular_numbers_long(self, l):
        if l <= 0:
            return 0
        return l + self.triangular_numbers_long(l-1)
```

Note that in Python, we don't need to specify the type of a variable (like `int` or `long`) when defining it. Also, note that I've added `self` as the first parameter to each method definition because these are instance methods and not static methods.