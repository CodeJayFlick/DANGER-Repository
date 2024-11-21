Here is the translation of the given Java code into Python:

```Python
class PairedPcodeArithmetic:
    def __init__(self, left_arith: 'PcodeArithmetic', right_arith: 'PcodeArithmetic'):
        self.left_arith = left_arith
        self.right_arith = right_arith

    def unary_op(self, op, sizeout, sizein1, in1):
        return (left_arith.unary_op(op, sizeout, sizein1, in1[0]),
                right_arith.unary_op(op, sizeout, sizein1, in1[1]))

    def binary_op(self, op, sizeout, sizein1, in1, sizein2, in2):
        return (left_arith.binary_op(op, sizeout, sizein1, in1[0], sizein2, in2[0]),
                right_arith.binary_op(op, sizeout, sizein1, in1[1], sizein2, in2[1]))

    def from_const(self, value: int | BigInteger, size):
        return (left_arith.from_const(value, size), right_arith.from_const(value, size))

    def is_true(self, cond):
        return left_arith.is_true(cond[0])

    def to_concrete(self, value):
        return left_arith.to_concrete(value[0])
```

Note that I've used type hints for the function parameters and variables. This is not necessary in Python as it does not have a static type system like Java or C#.