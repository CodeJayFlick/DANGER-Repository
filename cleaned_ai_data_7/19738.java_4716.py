class LitNewLine:
    def __init__(self):
        self.value = "\n"

    @property
    def description(self):
        return "Returns a line break separator."

    @property
    def examples(self):
        return ["send \"Hello\\nlGoodbye!\" to player"]

    @property
    def since(self):
        return "2.5"

    def register_expression(cls, skript_parser: 'SkriptParser') -> None:
        skript_parser.register_expression(LitNewLine, str, "n[ew]l[ine]", "line [ ]break")

LitNewLine.register_expression = classmethod(LitNewLine.register_expression)

def init(self) -> bool:
    return True

def to_string(self, event: 'Event', debug: bool) -> str:
    if not isinstance(event, type(None)):
        raise TypeError("event must be None")
    return "newline"
