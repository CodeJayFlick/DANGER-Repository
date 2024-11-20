class Tamer:
    def __init__(self):
        self.registered = False

    @staticmethod
    def register():
        if not Tamer.registered:
            Skript().register_expression(Tamer, "tamer")
            Tamer.registered = True

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parser_result: dict) -> bool:
        if not isinstance(parser_result["event"], EntityTameEvent):
            Skript().error("The expression 'tamer' may only be used in the entity tame event.")
            return False
        return True

    def get(self, e: Event) -> list:
        owner = (e.get_entity_tamed_event()).get_owner()
        if isinstance(owner, Player):
            return [owner]
        else:
            return []

    @staticmethod
    def get_return_type():
        return type("Player", (), {})

    def is_single(self) -> bool:
        return True

    def __str__(self, e: Event = None, debug: bool = False) -> str:
        if not isinstance(e, EntityTameEvent):
            return "the tamer"
