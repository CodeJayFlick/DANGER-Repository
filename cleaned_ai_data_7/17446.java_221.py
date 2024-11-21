class SubtractionExpression:
    def __init__(self, left_expression: 'Expression', right_expression: 'Expression'):
        super().__init__(left_expression, right_expression)

    def construct_transformer(self, left_parent_layer_point_reader: 'LayerPointReader', 
                               right_parent_layer_point_reader: 'LayerPointReader') -> 'ArithmeticBinaryTransformer':
        return ArithmeticSubtractionTransformer(left_parent_layer_point_reader, right_parent_layer_point_reader)

    def operator(self) -> str:
        return '-'
