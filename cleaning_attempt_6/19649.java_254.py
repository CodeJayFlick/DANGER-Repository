class PingExpression:
    def __init__(self):
        self.supported = hasattr(Player, 'spigot') and hasattr(Player.spigot(), 'get_ping')

    @property
    def name(self):
        return "Ping"

    @property
    def description(self):
        return ("Pings of players, as Minecraft server knows them. Note that they will almost certainly"
                +  " be different from the ones you'd get from using ICMP echo requests."
                +  " This expression is only supported on some server software (PaperSpigot).")

    @property
    def examples(self):
        return [
            {"command": "/ping <player=%player%>:",
             "trigger": "\ttrigger:",
             "output": "\"%arg-1%'s ping is %arg-1'\'s ping\""},
        ]

    @property
    def since(self):
        return "2.2-dev36"

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.supported:
            print("The ping expression is not supported on this server software.")
            return False

        self.expr = exprs[0]
        return True

    def convert(self, player):
        try:
            return long(player.spigot().get_ping())
        except AttributeError as e:
            raise Exception(f"Failed to get the ping of {player}: {e}")

    @property
    def return_type(self):
        return Long


# Registering expression with Skript
PropertyExpression.register(PingExpression, "ping", "players")
