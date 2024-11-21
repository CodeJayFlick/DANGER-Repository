class LocationExpression:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        from skript import Skript
        Skript.register_expression(LocationExpression, ExpressionType.SIMPLE,
                                   r"[the] [event-](location|position)")
        Skript.register_expression(LocationExpression, ExpressionType.COMBINED,
                                   r"[the] (location|position) %directions% [%location%]")

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result):
        if len(exprs) > 0:
            from skript.direction import Direction
            self.set_expr(Direction.combine(exprs[0], exprs[1]))
            return True
        else:
            self.set_expr(EventValueExpression(Location))
            return (self.get_expr()).init()

    def __str__(self, e: object = None, debug: bool = False):
        if isinstance(self.get_expr(), EventValueExpression):
            return "the location"
        else:
            from skript.direction import Direction
            return f"the location {self.get_expr().__str__(e, debug)}"


class WrapperExpression(Expression[Location]):
    def __init__(self):
        super().__init__()

    @property
    def expr(self) -> Location:
        pass

    @expr.setter
    def set_expr(self, value: Location):
        self.expr = value


from skript import Skript, ExpressionType
from typing import List, Type

EventValueExpression = ...  # Assuming this is a Python class equivalent to the Java one.
Direction = ...  # Assuming this is a Python class equivalent to the Java one.

if __name__ == "__main__":
    LocationExpression.register_expression()
