class ExprWorlds:
    def __init__(self):
        self.registered = Skript().register_expression(self)

    @property
    def name(self):
        return "Worlds"

    @property
    def description(self):
        return "All worlds of the server, useful for looping."

    @property
    def examples(self):
        return ["loop all worlds:", 
                "  broadcast \"You're in %loop-world%\" to loop-world"]

    @property
    def since(self):
        return "1.0"

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        return True

    def is_single(self) -> bool:
        return False

    @property
    def return_type(self):
        from bukkit import World
        return type(None)

    def get(self, e: Event) -> list[World]:
        return [world for world in Bukkit().get_worlds()]

    def iterator(self, e: Event) -> Iterator:
        return iter(Bukkit().get_worlds())

    def __str__(self):
        return "worlds"
