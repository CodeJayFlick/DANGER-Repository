class ArithmeticMultiplicationTransformer:
    def __init__(self, left_point_reader: 'LayerPointReader', right_point_reader: 'LayerPointReader'):
        super().__init__(left_point_reader, right_point_reader)

    def evaluate(self, left_operand: float, right_operand: float) -> float:
        return left_operand * right_operand
