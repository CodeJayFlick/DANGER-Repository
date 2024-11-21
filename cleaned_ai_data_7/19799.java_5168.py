class LiteralList:
    def __init__(self, literals: list, return_type: type, and_: bool):
        self.literals = literals
        self.return_type = return_type
        self.and_ = and_

    @property
    def expressions(self) -> list:
        return self.literals

    def get_array(self) -> list:
        return [literal.get_single() for literal in self.literals]

    def get_single(self) -> object:
        if len(self.literals) > 0:
            return self.literals[0].get_single()
        else:
            return None

    def get_all(self) -> list:
        return self.literals

    def get_converted_expression(self, to: tuple) -> 'LiteralList':
        converted_literals = []
        for literal in self.literals:
            if (converted_literal := literal.get_converted_expression(to)) is not None:
                converted_literals.append(converted_literal)
        if len(converted_literals) > 0:
            return LiteralList(converted_literals, to[0], self.and_, self)
        else:
            return None

    def simplify(self) -> 'LiteralList':
        simplified = True
        for literal in self.literals:
            simplified &= literal.is_single()
        if simplified:
            values = [literal.get_single() for literal in self.literals]
            return SimpleLiteral(values, self.return_type, self.and_)
        else:
            return self

class SimpleLiteral(LiteralList):
    def __init__(self, literals: list, return_type: type, and_: bool):
        super().__init__(literals, return_type, and_)

    @property
    def expressions(self) -> list:
        return self.literals

    def get_array(self) -> list:
        return [literal for literal in self.literals]

    def get_single(self) -> object:
        if len(self.literals) > 0:
            return self.literals[0]
        else:
            return None
