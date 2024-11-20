class PatternlessSymbol:
    def __init__(self):
        self.patexp = ConstantValue(0)

    def get_pattern_expression(self):
        return self.patexp


class SpecificSymbol:
    pass


class ConstantValue:
    def __init__(self, value):
        self.value = value

# Example usage
ps = PatternlessSymbol()
print(ps.get_pattern_expression().value)  # prints: 0
