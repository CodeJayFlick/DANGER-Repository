class PatternExpression:
    def __init__(self):
        pass

    @abstractmethod
    def get_value(self, walker) -> int:
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def restore_xml(self, parser: XmlPullParser, lang: SleighLanguage) -> None:
        raise NotImplementedError("Method not implemented")


def restore_expression(parser: XmlPullParser, lang: SleighLanguage) -> PatternExpression:
    element = parser.peek()
    if element.get_name() == "tokenfield":
        return TokenField()
    elif element.get_name() == "contextfield":
        return ContextField()
    elif element.get_name() == "intb":
        return ConstantValue()
    elif element.get_name() == "operand_exp":
        return OperandValue()
    elif element.get_name() == "start_exp":
        return StartInstructionValue()
    elif element.get_name() == "end_exp":
        return EndInstructionValue()
    elif element.get_name() == "plus_exp":
        return PlusExpression()
    elif element.get_name() == "sub_exp":
        return SubExpression()
    elif element.get_name() == "mult_exp":
        return MultExpression()
    elif element.get_name() == "lshift_exp":
        return LeftShiftExpression()
    elif element.get_name() == "rshift_exp":
        return RightShiftExpression()
    elif element.get_name() == "and_exp":
        return AndExpression()
    elif element.get_name() == "or_exp":
        return OrExpression()
    elif element.get_name() == "xor_exp":
        return XorExpression()
    elif element.get_name() == "div_exp":
        return DivExpression()
    elif element.get_name() == "minus_exp":
        return MinusExpression()
    elif element.get_name() == "not_exp":
        return NotExpression()
    else:
        return None

    # restore the xml
    restored_expression.restore_xml(parser, lang)
    return restored_expression


class AbstractClass(PatternExpression):
    @abstractmethod
    def __str__(self) -> str:
        raise NotImplementedError("Method not implemented")
