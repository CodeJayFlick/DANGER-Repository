class OpBehaviorFloatFloor:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_FLOOR)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float | int:
        if isinstance(in1, (int, float)):
            return self._evaluate_float(size_in, in1)
        elif isinstance(in1, int):
            return self._evaluate_int(size_in, in1)

    def _evaluate_float(self, size_in: int, in1: float) -> float:
        format = FloatFormatFactory.get_format(size_in)
        return format.op_floor(in1)

    def _evaluate_int(self, size_in: int, in1: int) -> int | float:
        if size_in == 4:
            # Assuming that the integer is a 32-bit signed integer
            return self._int_to_float(in1)
        elif size_in == 8:
            # Assuming that the integer is an 64-bit signed integer
            return self._long_to_float(in1)

    def _int_to_float(self, in1: int) -> float:
        return struct.unpack('f', struct.pack('i', in1))[0]

    def _long_to_float(self, in1: int) -> float:
        return struct.unpack('d', struct.pack('q', in1))[0]
