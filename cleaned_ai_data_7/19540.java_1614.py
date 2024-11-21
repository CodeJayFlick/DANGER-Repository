class ExprElement:
    def __init__(self):
        self.element = None
        self.expr = None
        self.number = None

    @staticmethod
    def register_expression():
        Skript.register_expression(ExprElement, Object, "(-1¦[the] first|1¦[the] last|0¦[a] random|2¦%-number%(st|nd|rd|th)) element [out] of %objects%", ExpressionType.PROPERTY)

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.expr = LiteralUtils.defend_expression(exprs[1])
        self.number = exprs[0]
        self.element = parse_result.mark
        return LiteralUtils.can_init_safely(self.expr)

    def get(self, event):
        os = self.expr.get_array(event)
        if len(os) == 0:
            return None

        o = None
        if self.element == -1:
            o = os[0]
        elif self.element == 1:
            o = os[-1]
        elif self.element == 2:
            number = self.number.get_single(event)
            if number is None or number.value < len(os) or number.value >= 0:
                return None
            o = os[number.value - 1]
        else:
            o = CollectionUtils.get_random(os)

        r = [o]
        return r

    def get_converted_expression(self, to):
        conv_expr = self.expr.get_converted_expression(to)
        if conv_expr is None:
            return None
        expr_element = ExprElement()
        expr_element.element = self.element
        expr_element.expr = conv_expr
        expr_element.number = self.number
        return expr_element

    def is_single(self):
        return True

    def get_return_type(self):
        return self.expr.get_return_type()

    def __str__(self, event=None, debug=False):
        prefix = None
        if self.element == -1:
            prefix = "the first"
        elif self.element == 1:
            prefix = "the last"
        elif self.element == 0:
            prefix = "a random"
        elif self.element == 2:
            assert self.number is not None
            prefix = "the "
            if isinstance(self.number, Literal):
                number = self.number.get_single()
                if number is None:
                    return f"{prefix}th element of {self.expr.__str__(event=event, debug=debug)}"
                else:
                    return f"{prefix}{StringUtils.fancy_order_number(number.value)}th element of {self.expr.__str__(event=event, debug=debug)}"
            else:
                return f"{prefix}{self.number.__str__(event=event, debug=debug)}th element of {self.expr.__str__(event=event, debug=debug)}"
        else:
            raise ValueError("Invalid value for 'element'")

        if event is not None and debug:
            return f"({prefix} element out) of {self.expr.__str__(event=event, debug=True)}"
        elif event is not None:
            return f"{prefix} element of {self.expr.__str__(event=event, debug=False)}"
        else:
            return f"{prefix} element of {self.expr}"
