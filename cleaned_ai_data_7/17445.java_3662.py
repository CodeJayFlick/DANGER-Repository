class MultiplicationExpression:
    def __init__(self, left_expression: 'Expression', right_expression: 'Expression'):
        super().__init__(left_expression, right_expression)

    def construct_transformer(self, left_parent_layer_point_reader: 'LayerPointReader',
                               right_parent_layer_point_reader: 'LayerPointReader') -> 'ArithmeticBinaryTransformer':
        return ArithmeticMultiplicationTransformer(left_parent_layer_point_reader,
                                                     right_parent_layer_point_reader)

    def operator(self) -> str:
        return "*"


class Expression:
    pass


class LayerPointReader:
    pass


class ArithmeticBinaryTransformer:
    pass


class ArithmeticMultiplicationTransformer(ArithmeticBinaryTransformer):
    def __init__(self, left_parent_layer_point_reader: 'LayerPointReader',
                 right_parent_layer_point_reader: 'LayerPointReader'):
        super().__init__()
