Here is the translation of the given C++ code into Python:

```Python
class LVALongTest1:
    def test1_2_long(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2(w)
        return z

    def callsReturnLongIntInt(self, x: int, y: int) -> int:
        a = self.returnLongIntInt(x, y)
        return a

    def test2(self, a: int) -> int:
        return a + a

    def test3(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2(w)
        return w

    def test4(self) -> int:
        z = self.test2(0x1234)
        return z

    def test5(self) -> int:
        z = self.test2(0)
        return z

    def returnLongIntInt(self, x: int, y: int) -> int:
        return 0
```

Please note that Python does not have an exact equivalent of C++'s `long` type. In this translation, I used the built-in integer type (`int`) to represent the values returned by these methods.