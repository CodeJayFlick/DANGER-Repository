class MinusExpression(UnaryExpression):
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, pattern_expression):
        super().__init__(location, pattern_expression)

    def get_value(self, parser_walker):
        val = self.get_unary().get_value(parser_walker)
        return -val

    def get_sub_value(self, replace, list_pos):
        val = self.get_unary().get_sub_value(replace, list_pos)
        return -val

    def save_xml(self, print_stream):
        print_stream.write("<minus_exp>\n")
        super().save_xml(print_stream)
        print_stream.write("</minus_exp>\n")

class UnaryExpression:
    pass
