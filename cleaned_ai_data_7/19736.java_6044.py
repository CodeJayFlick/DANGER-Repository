class LitAt:
    def __init__(self):
        self.direction = Direction.ZERO
        self.is_directional = True

    @staticmethod
    def register_expression():
        Skript.register_expression(LitAt, Direction, "at")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        return True

    def __str__(self):
        return "at"
