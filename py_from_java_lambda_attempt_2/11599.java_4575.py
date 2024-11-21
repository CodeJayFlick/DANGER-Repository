Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorCopy:
    def __init__(self):
        super().__init__(PcodeOp.COPY)

    def evaluate_unary(self, sizeout: int, sizein: int, in1) -> long:
        return in1

    def evaluate_big_integer_unary(self, sizeout: int, sizein: int, in1: 'BigInteger') -> 'BigInteger':
        return in1
```

Note that Python does not have a direct equivalent to Java's `long` type. In this translation, I've used the built-in integer type (`int`) for simplicity and clarity. If you need more precise control over integer sizes (e.g., 32-bit or 64-bit), consider using libraries like `numpy` or `pandas`.