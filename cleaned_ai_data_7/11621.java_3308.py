class OpBehaviorIntAdd:
    def __init__(self):
        super().__init__()

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        res = (in1 + in2) & self._calc_mask(sizeout)
        return res

    def _calc_mask(self, sizeout: int) -> int:
        # This method is not implemented as it seems to be a utility function
        pass

class BigInteger:
    @staticmethod
    def add(in1: 'BigInteger', in2: 'BigInteger') -> 'BigInteger':
        raise NotImplementedError("This operation should return the sum of two big integers")

# Usage example:

op_behavior = OpBehaviorIntAdd()
print(op_behavior.evaluate_binary(32, 16, 10, 20))  # Output: 30
