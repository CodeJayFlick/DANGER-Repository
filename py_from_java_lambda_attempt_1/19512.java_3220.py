Here is a translation of the Java code into equivalent Python:

```Python
class ChatRecipients:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Chat Recipients"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return "Recipients of chat events where this is called."

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["chat recipients"]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "2.2-Fixes-v7, 2.2-dev35 (clearing recipients)"

    @since.setter
    def since(self, value):
        self._since = value

    def is_single(self):
        return False

    def get_return_type(self):
        from bukkit.entity import Player
        return Player

    def accept_change(self, mode):
        if mode == "add":
            return [Player]
        elif mode == "remove":
            return [Player]
        else:
            return []

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        from bukkit.event import AsyncPlayerChatEvent
        parser = get_parser()
        if not parser.is_current_event(AsyncPlayerChatEvent):
            error("Cannot use chat recipients expression outside of a chat event", ErrorQuality.SEMANTIC_ERROR)
            return False
        return True

    def __str__(self, event=None, debug=False):
        return "chat recipients"

    def get(self, event):
        from bukkit.event import AsyncPlayerChatEvent
        ae = event
        player_set = ae.get_recipients()
        return list(player_set)

    def change(self, event, delta, mode):
        if mode == "remove":
            for player in delta:
                ((AsyncPlayerChatEvent)event).get_recipients().remove(player)
        elif mode == "add":
            for player in delta:
                ((AsyncPlayerChatEvent)event).get_recipients().add(player)
        else:
            raise ValueError("Invalid change mode")
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code seems to have some dependencies on Bukkit (a Minecraft server modding API), which are not present in standard Python libraries.