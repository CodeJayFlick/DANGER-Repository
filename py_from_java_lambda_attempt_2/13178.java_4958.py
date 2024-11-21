Here is the translation of the given C++ code into Python:

```Python
class LVALong:
    def test1(self, a: int, b: int, c: int, d: int) -> int:
        w = a + b
        x = c + d
        y = self.test2(w)
        z = self.test2(x)
        return y + z

    def test1_1(self, a: int, b: int, c: int, d: int) -> int:
        w = a + b
        y = self.test2(w)
        x = a + b
        z = self.test2(x)
        return y + z

    def test1_2(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2(w)
        return z

    def test1_2_int(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2int(w)
        return z

    def test1_2_long(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2(w)
        return z

    def test2(self, a: int) -> int:
        return a + a

    def test2int(self, a: int) -> int:
        return a + a

    def test3(self, a: int, b: int, c: int, d: int) -> int:
        w = a + b
        x = c + d
        y = a + c
        z = b + d
        return w + x + y + z

    def mixed1(self, a: int, b: int) -> int:
        x = a + int(b)
        return x

    def mixed2(self, b: int, a: int) -> int:
        x = a + int(b)
        return x

    def mixed3(self, a: int, b: int, c: int, d: int) -> int:
        x = int(a)
        y = int(c)
        return x + y + b + d
```

Note that Python does not support unsigned integers (like `long` in C++), so I used the built-in integer type (`int`) for all variables. Also, note that there is no direct equivalent of `mixed1`, `mixed2`, and `mixed3` functions as they are trying to cast an integer to a long which doesn't exist in Python.