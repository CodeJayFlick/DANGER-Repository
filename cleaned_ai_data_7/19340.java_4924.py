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
