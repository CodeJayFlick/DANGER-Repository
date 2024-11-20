class OpBehaviorFloatTrunc:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_TRUNC)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float | int:
        if isinstance(in1, (int, float)):
            return FloatFormatFactory().get_float_format(size_in).op_trunc(in1, size_out)
        else:
            raise ValueError("Invalid input type")

    def evaluate_unary_big_int(self, size_out: int, size_in: int, in1) -> int | float:
        if isinstance(in1, (int)):
            return FloatFormatFactory().get_float_format(size_in).op_trunc(int(in1), size_out)
        else:
            raise ValueError("Invalid input type")
