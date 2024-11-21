Here is a translation of the Java code into equivalent Python:

```Python
class GravityExpression:
    def __init__(self):
        self.name = "Gravity"
        self.description = "If entity is affected by gravity or not, i.e., if it has Minecraft 1.10+ NoGravity flag."
        self.examples = ["set gravity of player off"]
        self.since = "2.2-dev21"

    def convert(self, e):
        return e.has_gravity()

    def get_property_name(self):
        return "gravity"

    def get_return_type(self):
        return bool

    def accept_change(self, mode):
        if mode in [set, reset]:
            return [bool]
        return None

    def change(self, event, delta=None, mode=set):
        for entity in self.get_expr().get_array(event):
            if delta is None:
                entity.set_gravity(True)
            else:
                entity.set_gravity(delta[0])
```

Please note that Python does not have direct equivalent of Java's static block or annotations. Also, the `@Nullable` annotation is used to indicate that a method parameter can be null in Java, but this concept doesn't exist directly in Python (although you could use type hints for it).