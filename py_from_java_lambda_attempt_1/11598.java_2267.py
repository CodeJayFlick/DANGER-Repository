Here is the translation of the given Java code into Python:

```Python
class OpBehaviorBoolXor:
    def __init__(self):
        super().__init__(PcodeOp.BOOL_XOR)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        return in1 ^ in2

    def evaluate_big_integer(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        from gmpy2 import mpz
        res = mpz(in1).xor(mpz(in2))
        return int(res)
```

Please note that Python does not have built-in support for arbitrary-precision integers like Java's BigInteger class. However, you can use the `gmpy2` library to achieve similar functionality.

Also, please be aware that this code is a direct translation of your given Java code and might need adjustments based on how it will actually be used in Python.