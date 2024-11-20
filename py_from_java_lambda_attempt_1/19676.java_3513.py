Here is a translation of the Java code into equivalent Python:

```Python
class WorldSeed:
    def __init__(self):
        self.name = "World Seed"
        self.description = ("The seed of given world. Note that it will be returned as Minecraft internally treats seeds, not as you specified it in world configuration.")
        self.examples = ["broadcast \"Seed: %seed of player's world%\""]

    def get(self, event):
        return [world.get_seed() for world in event]

class Expression:
    def __init__(self, exprs, matched_pattern, is_delayed, parser):
        self.exprs = exprs
        self.matched_pattern = matched_pattern
        self.is_delayed = is_delayed
        self.parser = parser

    def init(self):
        return True

def get_return_type():
    return long

class PropertyExpression:
    def __init__(self, event=None):
        if event is not None:
            print("the seed of " + str(event))
        else:
            print(Classes.get_debug_message(get_all()))

    @staticmethod
    def register_expression(cls, exprs, matched_pattern, parser):
        Skript.register_expression(cls, long, ExpressionType.PROPERTY, "[the] seed[es] (from|of) %worlds%", "%worlds%'[es] seed[s]")
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations. These are used for documentation purposes and can be replaced with docstrings in Python.

Also, the `get` method is a part of the `WorldSeed` class now as it seems to depend on some event which is passed to this method.