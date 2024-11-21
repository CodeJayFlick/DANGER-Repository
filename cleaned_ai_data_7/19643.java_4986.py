class OnlinePlayerCount:
    def __init__(self):
        self.is_real = None

    @property
    def description(self):
        return ["The amount of online players.", "This can be changed in a server list ping event only to show fake online player amount.",
                "'real online player count' always returns the real count of online players and can't be changed.",
                "",
                "Fake online player count requires PaperSpigot 1.12.2+."]

    @property
    def examples(self):
        return ["on server list ping:",
                "# This will make the max players count 5 if there are 4 players online.",
                "set the fake max players count to (online players count + 1)"]

    @property
    def since(self):
        return "2.3"

    def init(self, exprs=None, matched_pattern=0, is_delayed=False, parse_result=None):
        self.is_real = not PAPER_EVENT_EXISTS and parse_result.mark == 0 or parse_result.mark == 1

    def get(self, e):
        if self.is_real:
            return [len(PlayerUtils.get_online_players())]
        else:
            return [(e).get_num_players()]

    def accept_change(self, mode=None):
        if not self.is_real and PAPER_EVENT_EXISTS:
            if parse_result.has_delay_before():
                print("Can't change the shown online players count anymore after the server list ping event has already passed")
                return None
            match mode:
                case "set":
                    return [int]
                case "add" | "remove" | "delete" | "reset":
                    return [int]

    def change(self, e=None, delta=None, mode=None):
        if not self.is_real and PAPER_EVENT_EXISTS:
            event = PaperServerListPingEvent()
            match mode:
                case "set":
                    event.set_num_players(int(delta[0]))
                case "add":
                    event.set_num_players(event.get_num_players() + int(delta[0]))
                case "remove":
                    event.set_num_players(event.get_num_players() - int(delta[0]))
                case "delete" | "reset":
                    event.set_num_players(len(PlayerUtils.get_online_players()))

    def is_single(self):
        return True

    @property
    def return_type(self):
        return Long

    def __str__(self, e=None, debug=False):
        if self.is_real:
            return f"the count of real max players"
        else:
            return "max players"

PAPER_EVENT_EXISTS = Skript.class_exists("com.destroystokyo.paper.event.server.PaperServerListPingEvent")
