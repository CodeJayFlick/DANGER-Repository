Here is the translation of the given Java code into Python:

```Python
class Condition:
    def __init__(self):
        self.negated = False

    @abstractmethod
    def check(self, e: 'org.bukkit.event.Event') -> bool:
        pass

    def run(self, e: 'org.bukkit.event.Event') -> bool:
        return self.check(e)

    def set_negated(self, invert: bool) -> None:
        self.negated = invert

    @property
    def is_negated(self) -> bool:
        return self.negated


@staticmethod
def parse(s: str, default_error: str = None) -> 'Condition':
    s = s.strip()
    while s.startswith('(') and SkriptParser.next(s, 0, ParseContext.DEFAULT) == len(s):
        s = s[1:-1]
    return Condition(Skript.get_conditions().iterator(), default_error)
```

Please note that Python does not support abstract classes or methods. Instead, you can use the `abc` module to create an Abstract Base Class (ABC).