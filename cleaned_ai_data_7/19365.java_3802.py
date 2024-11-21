class PlayerInfoVisibility:
    def __init__(self):
        self.should_hide = None

    @property
    def should_hide(self):
        return self._should_hide

    @should_hide.setter
    def should_hide(self, value):
        self._should_hide = value

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool) -> bool:
        if not hasattr(com.destroystokyo.paper.event.server.PaperServerListPingEvent, 'class'):
            print("The player info visibility effect requires Paper 1.12.2 or newer")
            return False
        elif not isinstance(exprs[0], com.destroystokyo.paper.event.server.PaperServerListPingEvent):
            print("The player info visibility effect can't be used outside of a server list ping event")
            return False
        elif is_delayed:
            print("Can't change the player info visibility anymore after the server list ping event has already passed")
            return False

        self.should_hide = matched_pattern == 0
        return True

    def execute(self, e: com.destroystokyo.paper.event.server.PaperServerListPingEvent):
        e.set-hide_players(self.should_hide)

    def __str__(self) -> str:
        if self.should_hide:
            return "hide player info in the server list"
        else:
            return "show player info in the server list"

# Registering the effect
Skript.register_effect(PlayerInfoVisibility, ["hide [all] player [related] info[rmation] [(in|on|from) [the] server list]", "(show|reveal) [all] player [related] info[rmation] [(in|to|on|from) [the] server list]"], "Player Info Visibility")
