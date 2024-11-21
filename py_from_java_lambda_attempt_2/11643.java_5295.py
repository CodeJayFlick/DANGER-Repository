Here's a translation of the given Java code into equivalent Python:

```Python
class OpBehaviorIntZext:
    def __init__(self):
        super().__init__(PcodeOp.INT_ ZEXT)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> long:
        return in1

    def evaluate_big_integer_unary(self, size_out: int, size_in: int, in1: 'BigInteger') -> 'BigInteger':
        return in1
```

Please note that Python does not have a direct equivalent of Java's BigInteger class. The above code assumes you are using the `decimal` module from Python standard library for big integer operations.

Also, there is no direct translation for the commented out method (`recover_input_unary`) as it seems to be related to error handling and may require additional context or implementation details that were not provided in the original Java code.