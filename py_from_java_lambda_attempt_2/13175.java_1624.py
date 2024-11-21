Here is the translation of the given Java code into equivalent Python:

```Python
class LongReturnerTests:
    def calls_return_long_void(self):
        a = self.return_long_void()
        return a

    def calls_return_long_int(self, x: int) -> long:
        a = self.return_long_int(x)
        return a

    def calls_return_long_int_int(self, x: int, y: int) -> long:
        a = self.return_long_int_int(x, y)
        return a

    def calls_return_long_long(self, x: long) -> long:
        a = self.return_long_long(x)
        return a

    def calls_return_long_long_long(self, x: long, y: long) -> long:
        a = self.return_long_long_long(x, y)
        return a

    def calls_return_long_int_long(self, x: int, y: long) -> long:
        a = self.return_long_int_long(x, y)
        return a

    def calls_return_int_int_long(self, x: int, y: long) -> int:
        a = self.return_int_int_long(x, y)
        return a

    def calls_return_long_long_int(self, x: long, y: int) -> long:
        a = self.return_long_long_int(x, y)
        return a

    @staticmethod
    def static_calls_return_long_long_int(x: long, y: int) -> long:
        a = LongReturnerTests.static_return_long_long_int(x, y)
        return a

    @staticmethod
    def static_calls_return_long_int_long(y: long, x: int) -> long:
        a = LongReturnerTests.static_return_long_int_long(y, x)
        return a


    def return_long_void(self):
        return 1L

    def return_long_int(self, x: int) -> long:
        return 1L

    def return_long_int_int(self, x: int, y: int) -> long:
        return 1L

    def return_long_long(self, x: long) -> long:
        return 1L

    def return_long_long_long(self, x: long, y: long) -> long:
        return 1L

    def return_long_int_long(self, x: int, y: long) -> long:
        return 1L

    def return_int_int_long(self, x: int, y: long) -> int:
        return 1

    def return_long_long_int(self, x: long, y: int) -> long:
        return 1L

    @staticmethod
    def static_return_long_long_int(x: long, y: int) -> long:
        return 1L

    @staticmethod
    def static_return_long_int_long(y: long, x: int) -> long:
        return 1L


# Create an instance of the class and call its methods.
long_returner_tests = LongReturnerTests()
print(long_returner_tests.calls_return_long_void())
```

Note that Python does not have a built-in `long` type like Java. Instead, you can use the `int` type for integers and the `float` or `decimal` types if you need to represent very large numbers precisely.