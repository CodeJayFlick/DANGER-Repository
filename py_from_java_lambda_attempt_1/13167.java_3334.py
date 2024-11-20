Here is the translation of the given Java code into Python:

```Python
class InvokeStatic:
    def call_ints(self):
        a = 2
        b = 1
        a = self.func1_1(a)
        b = self.func1_1_1(a, b)
        return a + b

    def func0_0(self):
        pass

    def func0_1(self, a: int) -> None:
        a += 1

    def func0_2(self, a: int) -> None:
        a += 1

    def func1_1(self, a: int) -> int:
        return a + 10

    def func1_1_1(self, a: int, b: int) -> int:
        return a + b

    def func2_2(self, a: int) -> int:
        return a + 1

    def func2_2_2(self, a: int, b: int) -> int:
        return a + b

    def mixed(self, a: int, b: long, c: int, d: long) -> int:
        return a + int(b) + c + int(d)

    def get_long(self):
        return 1

    def calls_long_returner(self):
        a = self.get_long()
        return a
```

Please note that Python does not support direct equivalent of Java's static methods. In the given code, I have used instance methods (`self`) as they are more common in Python and do not require any additional setup like `public` or `static`.