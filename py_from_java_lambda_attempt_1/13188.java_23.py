Here is the translation of the given Java code into Python:

```Python
class ReturnTests:
    def calls_return_long_int_long(self, x: int, y: long) -> long:
        a = self.return_long_int_long(x, y)
        return a

    def calls_return_int_int_long(self, x: int, y: long) -> int:
        a = self.return_int_int_long(x, y)
        return a

    def calls_return_long_long_int(self, x: long, y: int) -> long:
        a = self.return_long_long_int(x, y)
        return a

    def calls_return_int_long_int(self, x: long, y: int) -> int:
        a = self.return_int_long_int(x, y)
        return a

    def return_long_int_long(self, x: int, y: long) -> long:
        return 1

    def return_int_int_long(self, x: int, y: long) -> int:
        return 1

    def return_long_long_int(self, x: long, y: int) -> long:
        return 1

    def return_int_long_int(self, x: long, y: int) -> int:
        return 1
```

Please note that Python does not have an exact equivalent of Java's `long` data type. In this translation, I used the built-in integer type (`int`) for all values, as it is sufficient to represent integers up to a certain size (which depends on your system). If you need to work with larger integers or decimal numbers, consider using Python's `decimal` module or third-party libraries like `gmpy2`.