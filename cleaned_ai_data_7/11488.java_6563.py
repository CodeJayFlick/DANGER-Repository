class MultExpression:
    def __init__(self):
        pass

    def get_value(self, walker):
        try:
            left_val = self.get_left().get_value(walker)
            right_val = self.get_right().get_value(walker)
            return left_val * right_val
        except Exception as e:
            raise MemoryAccessException(str(e))

    def __str__(self):
        return f"({self.get_left()} * {self.get_right()})"

class BinaryExpression:
    pass

class PatternExpression:
    def get_value(self, walker):
        # implement this method according to your needs
        pass

    def get_left(self):
        # implement this method according to your needs
        pass

    def get_right(self):
        # implement this method according to your needs
        pass
