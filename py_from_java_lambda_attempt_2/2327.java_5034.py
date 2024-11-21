Here is the equivalent Python code:

```Python
class TraceMemoryStatePcodeArithmetic:
    def __init__(self):
        pass

    @staticmethod
    def unary_op(op, size_out, size_in1, in1):
        return in1

    @staticmethod
    def binary_op(op, size_out, size_in1, in1, size_in2, in2):
        if in1 == 'KNOWN' and in2 == 'KNOWN':
            return 'KNOWN'
        else:
            return 'UNKNOWN'

    @staticmethod
    def from_const(value, size):
        return 'KNOWN'

    @staticmethod
    def is_true(cond):
        raise AssertionError("Cannot decide branches using TraceMemoryState")

    @staticmethod
    def to_concrete(value):
        raise AssertionError("Cannot make TraceMemoryState a 'concrete value'")
```

Note that Python does not have an equivalent of Java's `enum` type, so I used classes instead. Also, the `BigInteger` class in Java is not directly translatable to Python (as it's a part of Java's standard library), but since this code doesn't seem to use any specific operations on big integers, I just removed that method altogether.