Here is the translation of the given Java code into Python:

```Python
import random

class CondChance:
    def __init__(self):
        self.skript = Skript()

    @property
    def chance(self):
        return self._chance

    @chance.setter
    def chance(self, value):
        self._chance = value

    @property
    def percent(self):
        return self._percent

    @percent.setter
    def percent(self, value):
        self._percent = value

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if len(exprs) != 1:
            raise ValueError("Expected exactly one expression")
        self.chance = float(exprs[0])
        self.percent = parser.mark == 1
        return True

    def check(self, e):
        n = self.chance.get_single(e)
        if n is None:
            return False
        return random.random() < (self.percent and n / 100 or n)

    def __str__(self, e=None, debug=False):
        return f"chance of {self.chance:.0f}{'' if not self.percent else '%'}"

class Skript:
    @staticmethod
    def register_condition(cls, pattern):
        pass

# Example usage:

cond = CondChance()
exprs = [50.5]
matched_pattern = 1
is_delayed = None
parser = ParseResult()

if cond.init(exprs, matched_pattern, is_delayed, parser):
    print(cond.check(None))  # Output: True or False
else:
    print("Initialization failed")
```

Please note that the `Skript` class and its methods are not part of Python's standard library. They seem to be custom classes used in this specific context.