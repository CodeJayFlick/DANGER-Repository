Here is the translation of the Java code to Python:
```
import skript

class EffExceptionDebug:
    def __init__(self):
        Skript.register_effect(self.__class__, "cause exception")

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        return True

    def execute(self, e: Event):
        skript.exception("Created by a script (debugging)...")

    def __str__(self, e: Optional[Event] = None, debug: bool = False) -> str:
        return "cause exception"
```
Note that I've used the `skript` module as a placeholder for the equivalent functionality in Java. In Python, you would need to implement your own logic for registering effects and handling exceptions.

Also, keep in mind that this is just one possible translation of the code, and there may be other ways to achieve the same result using Python.