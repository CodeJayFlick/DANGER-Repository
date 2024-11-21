Here is the translation of the given Java code into equivalent Python:

```Python
class BigIntegerPcodeArithmetic:
    def __init__(self):
        self.INSTANCE = self

    def unary_op(self, op, sizeout, sizein1, in1):
        return op.evaluate_unary(sizeout, sizein1, in1)

    def binary_op(self, op, sizeout, sizein1, in1, sizein2, in2):
        return op.evaluate_binary(sizeout, sizein1, in1, in2)

    @staticmethod
    def from_const(value: int | BigInteger, size) -> int | BigInteger:
        if isinstance(value, int):
            return BigInteger(str(value))
        else:
            return value

    @classmethod
    def is_true(cls, cond: BigInteger) -> bool:
        return not cond.equals(BigInteger.ZERO)

    @staticmethod
    def to_concrete(value: int | BigInteger) -> int | BigInteger:
        return value


# Example usage:

class BinaryOpBehavior:
    def evaluate_binary(self, sizeout, sizein1, in1, in2):
        # Your binary operation logic here
        pass

class UnaryOpBehavior:
    def evaluate_unary(self, sizeout, sizein1, in1):
        # Your unary operation logic here
        pass


# Usage example:

op_behavior = BinaryOpBehavior()
arithmetic = BigIntegerPcodeArithmetic()

result = arithmetic.binary_op(op_behavior, 0, 0, 10, 20, 30)
print(result)  # Output: The result of the binary operation

```

This Python code is equivalent to the given Java code. It defines a class `BigIntegerPcodeArithmetic` with methods for performing unary and binary operations on big integers.