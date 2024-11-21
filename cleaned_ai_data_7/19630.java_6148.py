class MeExpression:
    def __init__(self):
        self.registered = False

    @staticmethod
    def register():
        if not MeExpression.registered:
            Skript().register_expression(MeExpression, "me", "my[self]")

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        return isinstance(parse_result.event, EffectCommandEvent)

    @staticmethod
    @nullable
    def get(event: Event) -> list[Player]:
        command_sender = (event).get_sender()
        if isinstance(command_sender, Player):
            return [command_sender]
        return []

    def is_single(self) -> bool:
        return True

    def get_return_type(self) -> type[Player]:
        return Player

    @staticmethod
    def to_string(event: Event, debug: bool) -> str:
        return "me"
