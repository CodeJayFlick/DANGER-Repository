Here is the translation of the given Java code into Python:

```Python
class SimpleEvent:
    def __init__(self):
        pass

    def check(self, e: 'org.bukkit.event.Event') -> bool:
        return True

    def init(self, args: list[object], matched_pattern: int, parser: object) -> bool:
        if len(args) != 0:
            raise Exception("Invalid use of SimpleEvent")
        return True

    def __str__(self, e: 'org.bukkit.event.Event', debug: bool) -> str:
        return "simple event"
```

Please note that Python does not have direct equivalent to Java's `@Override` annotation. Also, the type hints are used in this translation for clarity and readability purposes only, as they do not affect the functionality of the code.