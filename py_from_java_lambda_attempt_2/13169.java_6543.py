Here is the translation of the given Java code into Python:

```Python
class InvokeVirtual1:
    def func0_2(self, a):
        a += 1
        return

    def get_long(self):
        return 1L

    def long_and_void_test(self, a, b):
        c = a + b
        self.func0_2(c)
        d = self.get_long()
        return c + d


# Example usage:
obj = InvokeVirtual1()
print(obj.long_and_void_test(10, 20))
```

Please note that Python does not have an exact equivalent of Java's `long` type. In this translation, I used the built-in integer type (`int`) for simplicity and clarity. If you need to work with very large integers (beyond what can be represented by a standard Python int), consider using the `decimal` module or other libraries that support arbitrary-precision arithmetic.