class ExprWorld:
    def __init__(self):
        self.register_expression()

    def register_expression(self):
        Skript().register_expression(ExprWorld(), World, "the world [of %locations/entities%]", "%locations/entities%'[s] world")

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parser: dict) -> bool:
        if not exprs or len(exprs) == 0:
            return False
        expr = exprs[0]
        if expr is None:
            expr = EventValueExpression(World)
            if not expr.init():
                return False
        self.set_expr(expr)
        return True

    def get(self, e: dict, source: list) -> list:
        if isinstance(source, list):
            return [World] * len(source)
        converter = Converter()
        result = []
        for o in source:
            if isinstance(o, Entity):
                if self.get_time() > 0 and isinstance(e, PlayerTeleportEvent) and o == e['player'] and not Delay.is_delayed(e):
                    return [(PlayerTeleportEvent)(e)['to'].get_world()]
                else:
                    return [o.get_world()]
            elif isinstance(o, Location):
                return [o.get_world()]
        assert False
        return []

    def accept_change(self, mode: str) -> list or None:
        if mode == 'set':
            return [World]
        return None

    def change(self, e: dict, delta: list, mode: str):
        for o in self.get_expr().get_array(e):
            if isinstance(o, Location):
                (Location)(o).set_world(delta[0])

    def set_time(self, time: int) -> bool:
        return super().set_time(time, self.get_expr(), 'PlayerTeleportEvent')

    @property
    def get_return_type(self) -> type:
        return World

    def __str__(self, e: dict or None = None, debug: bool = False):
        if not self.get_expr().is_default():
            return "the world of " + str(self.get_expr())
        else:
            return "the world"
