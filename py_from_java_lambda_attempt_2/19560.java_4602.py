Here is a translation of the Java code into equivalent Python:

```Python
class ExplosionYield:
    def __init__(self):
        pass

    @property
    def description(self):
        return ["The yield of the explosion in an explosion prime event.",
                "When changing the yield, values less than 0 will be ignored.",
                "Read <https://minecraft.gamepedia.com/Explosion> for more information"]

    @property
    def examples(self):
        return ["on explosion prime:",
                "\tset the yield of the explosion to 10"]

    @property
    def events(self):
        return ["explosion prime"]

    @property
    def since(self):
        return "2.5"

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.is_current_event(ExplosionPrimeEvent()):
            raise ValueError("The explosion radius is only usable in explosion prime events")
        return True

    @staticmethod
    def register_expression():
        pass  # equivalent to Skript.registerExpression()

    def get(self, event):
        return [(event.get_radius(),)]

    def accept_change(self, mode):
        if mode in [ChangeMode.SET, ChangeMode.ADD, ChangeMode.REMOVE, ChangeMode.DELETE]:
            return [Number]
        else:
            return None

    def change(self, event, delta, mode):
        f = 0
        if delta is not None and len(delta) > 0:
            f = float(delta[0])
        if f < 0:  # Negative values will throw an error.
            return
        e = ExplosionPrimeEvent(event)
        if mode == ChangeMode.SET:
            e.set_radius(f)
        elif mode in [ChangeMode.ADD, ChangeMode.REMOVE]:
            add = e.get_radius() + f
            if add < 0:  # Negative values will throw an error.
                return
            e.set_radius(add)
        elif mode == ChangeMode.DELETE:
            e.set_radius(0)

    def is_single(self):
        return True

    @property
    def return_type(self):
        return Number

    def __str__(self, event=None, debug=False):
        if event is not None and isinstance(event, ExplosionPrimeEvent):
            return "the yield of the explosion"
```

Note that Python does not have direct equivalents to Java's `@Name`, `@Description`, etc. annotations, so I've simply included these as properties on the class.