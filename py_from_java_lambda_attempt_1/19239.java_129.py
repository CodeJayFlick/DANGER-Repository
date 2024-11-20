Here's a translation of your Java code into Python:

```Python
class CondIsAlive:
    def __init__(self):
        self.is_negated = None

    @property
    def is_negated(self):
        return self._is_negated

    @is_negated.setter
    def is_negated(self, value):
        self._is_negated = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(parse_result.mark) == 1:
            self.is_negated = True
        return super().init(exprs, matched_pattern, is_delayed, parse_result)

    def check(self, e):
        return not self.is_negated and not e.dead

    def get_property_name(self):
        return "dead" if self.is_negated else "alive"
```

This Python code does the same thing as your Java code. It defines a class `CondIsAlive` with methods to initialize itself (`init`), check whether an entity is alive or dead (`check`), and get its property name based on negation status (`get_property_name`).