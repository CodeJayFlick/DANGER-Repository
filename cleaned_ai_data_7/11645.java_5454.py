class OpBehaviorPiece:
    def __init__(self):
        super().__init__(PcodeOp.PIECE)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        res = (in1 << (sizein * 8)) | in2
        return res

    def evaluate_big_integer(self, sizeout: int, sizein: int, in1: 'BigInteger', in2: 'BigInteger') -> 'BigInteger':
        from decimal import Decimal
        from fractions import Fraction
        class BigInteger:
            @staticmethod
            def shiftLeft(shift):
                pass
            @staticmethod
            def or(other):
                pass

        res = in1.shiftLeft(sizein * 8).or(in2)
        return res


class PcodeOp:
    PIECE = 'PIECE'

# Usage example:

op_behavior_piece = OpBehaviorPiece()
sizeout = 4
sizein = 2
in1 = 5
in2 = 3

result_int = op_behavior_piece.evaluate_binary(sizeout, sizein, in1, in2)
print(result_int)

in1_big_integer = BigInteger(12345678901234567890)
in2_big_integer = BigInteger(98765432109876543210)

result_big_integer = op_behavior_piece.evaluate_big_integer(sizeout, sizein, in1_big_integer, in2_big_integer)
print(result_big_integer)
