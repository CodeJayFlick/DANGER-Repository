Here is a translation of the given Java code into equivalent Python:

```Python
class SpawnReasonExpression:
    def __init__(self):
        self.super().__init__()

    @property
    def name(self):
        return "Spawn Reason"

    @property
    def description(self):
        return ("The spawn reason in a spawn event.")

    @property
    def examples(self):
        return ["on spawn:", "\tspawn reason is reinforcements or breeding"]

    @property
    def since(self):
        return "2.3"


def register_expression():
    Skript.register_expression(SpawnReasonExpression, SpawnReason)


register_expression()

class EventValueExpression:
    pass


class ExpressionType:
    SIMPLE = 'SIMPLE'
```

Please note that Python does not have direct equivalent of Java's `@` symbol for annotations or the concept of static blocks.