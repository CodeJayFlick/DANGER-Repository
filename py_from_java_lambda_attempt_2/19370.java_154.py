Here is the translation of the Java code to Python:

```Python
class Push:
    def __init__(self):
        self.entities = None
        self.direction = None
        self.speed = None

    @staticmethod
    def register_effect():
        Skript.register_effect("(push|thrust) %entities% %direction% [(at|with) (speed|velocity|force) %-number%]")

    def init(self, exprs):
        if len(exprs) != 3:
            return False

        self.entities = exprs[0]
        self.direction = exprs[1]
        self.speed = exprs[2]

        return True

    def execute(self, e):
        direction = self.direction.get_single(e)
        if direction is None:
            return

        speed = self.speed
        if speed and not speed.get_single(e):
            return

        ents = self.entities.get_array(e)
        for en in ents:
            assert en is not None
            mod = direction.get_direction(en)
            if speed:
                mod.normalize().multiply(speed.get_single(e).double_value())
            en.set_velocity(en.get_velocity().add(mod))

    def __str__(self, e=None, debug=False):
        return f"push {self.entities} {self.direction}" + (f" at speed {self.speed}" if self.speed else "")
```

Note that this is a direct translation of the Java code to Python. The original code has some complex logic and annotations which may not be directly translatable or idiomatic in Python.