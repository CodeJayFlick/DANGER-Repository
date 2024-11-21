class Lightning:
    def __init__(self):
        self.locations = None
        self.effect_only = False

    @staticmethod
    def register_effect():
        Skript.register_effect(Lightning, "(create|strike) lightning(1¦[  ]effect|) %directions% %locations%")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.locations = Direction.combine(exprs[0], exprs[1])
        self.effect_only = parse_result.mark == 1
        return True

    def execute(self, e):
        for l in self.locations.get_array(e):
            if self.effect_only:
                l.world.strike_lightning_effect(l)
            else:
                l.world.strike_lightning(l)

    def __str__(self, e=None, debug=False):
        return f"strike lightning {'' if not self.effect_only else 'effect '} {self.locations.__str__(e, debug)}"


class Direction:
    @staticmethod
    def combine(direction_expr, location_expr):
        # implement this method to handle direction and location expressions
        pass


class Location:
    def __init__(self, world):
        self.world = world

    def get_world(self):
        return self.world

    def strike_lightning_effect(self):
        # implement this method for the lightning effect
        pass

    def strike_lightning(self):
        # implement this method for regular lightning
        pass


class Skript:
    @staticmethod
    def register_effect(effect_class, pattern):
        # implement this method to handle registering effects with patterns
        pass


# Example usage:

lightning = Lightning()
Skript.register_effect(Lightning)
