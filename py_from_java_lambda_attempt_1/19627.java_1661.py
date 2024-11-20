Here is the translation of the given Java code into Python:

```Python
class MaxMinecartSpeed:
    def __init__(self):
        self.registered = False

    @staticmethod
    def register():
        if not MaxMinecartSpeed.registered:
            from skript import Expression, NumberExpression
            Expression.register(MaxMinecartSpeed(), "max[imum] minecart (speed|velocity)", ["entities"])
            MaxMinecartSpeed.registered = True

    def convert(self, entity):
        if isinstance(entity, Minecart):
            return entity.max_speed
        else:
            return None

    def accept_change(self, mode):
        if mode in [ChangeMode.ADD, ChangeMode.REMOVE, ChangeMode.RESET, ChangeMode.SET]:
            return [Number]
        else:
            return []

    def change(self, event, delta=None, mode=0):
        if not delta and mode == ChangeMode.RESET:
            for entity in self.get_expr().get_array(event):
                if isinstance(entity, Minecart):
                    entity.max_speed = 0.4
        elif mode == ChangeMode.SET:
            for entity in self.get_expr().get_array(event):
                if isinstance(entity, Minecart):
                    entity.max_speed = delta[0]
        elif mode in [ChangeMode.ADD, ChangeMode.REMOVE]:
            mod = -1 if mode == ChangeMode.REMOVE else 1
            for entity in self.get_expr().get_array(event):
                if isinstance(entity, Minecart):
                    minecart = Minecart(entity)
                    minecart.max_speed += delta[0] * mod

    def get_return_type(self):
        return Number

    @property
    def property_name(self):
        return "max minecart speed"
```

Please note that this Python code is not a direct translation of the given Java code. It's an equivalent implementation in Python, and it might have some differences due to language-specific features or nuances.