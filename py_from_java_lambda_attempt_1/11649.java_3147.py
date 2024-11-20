Here is the translation of the Java code to Python:
```
class UnaryOpBehavior:
    def __init__(self, opcode):
        pass  # equivalent to super(opcode)

    def evaluate_unary_long(self, sizeout: int, sizein: int, unsigned_in1: int) -> int:
        """Evaluate the unary operation using long data"""
        raise NotImplementedError("Abstract method")

    def evaluate_unary_big_int(self, sizeout: int, sizein: int, unsigned_in1: BigInteger) -> BigInteger:
        """Evaluate the unary operation using BigInteger data"""
        raise NotImplementedError("Abstract method")
```
Note that I've kept the abstract methods as is, since they are intended to be implemented by subclasses.