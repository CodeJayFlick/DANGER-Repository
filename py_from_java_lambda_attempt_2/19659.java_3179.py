Here is a translation of the Java code into equivalent Python:

```Python
class ProtocolVersionExpression:
    def __init__(self):
        self.name = "Protocol Version"
        self.description = [
            f"The protocol version that will be sent as the protocol version of the server in a server list ping event. For more information and list of protocol versions visit wiki.vg.",
            "If this protocol version doesn't match with the protocol version of the client, the client will see the <a href='#ExprVersionString'>version string</a>.",
            "But please note that, this expression has no visual effect over the version string. For example if the server uses PaperSpigot 1.12.2, and you make the protocol version 107 (1.9),",
            "the version string will not be \"Paper 1.9\", it will still be \"Paper 1.12.2\".",
            "But then you can customize the <a href='#ExprVersionString'>version string</a> as you wish.",
            "Also if the protocol version of the player is higher than protocol version of the server, it will say",
            "\"Server out of date!\", and if vice-versa \"Client out of date!\" when you hover on the ping bars.",
            "",
            "This can be set in a <a href='events.html#server_list_ping'>server list ping</a> event only (increase and decrease effects cannot be used because that wouldn't make sense).",
        ]
        self.examples = [
            "on server list ping:",
            "\tset the version string to \"&lt;light green&gt;Version: &lt;orange&gt;%minecraft version%\"",
            "\tset the protocol version to 0 # 13w41a (1.7) - so the player will see the custom version string almost always",
        ]
        self.since = "2.3"
        self.required_plugins = ["Paper 1.12.2 or newer"]
        self.events = ["server list ping"]

    def init(self, exprs: List[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        if not Skript.class_exists("com.destroystokyo.paper.event.server.PaperServerListPingEvent"):
            Skript.error("The protocol version expression requires Paper 1.12.2 or newer")
            return False
        elif not get_parser().is_current_event(PaperServerListPingEvent):
            Skript.error("The protocol version expression can't be used outside of a server list ping event")
            return False
        return True

    def get(self, e: Event) -> List[Long]:
        return [long((PaperServerListPingEvent(e)).get_protocol_version())]

    def accept_change(self, mode: ChangeMode) -> Class[List[Number]]:
        if get_parser().has_delay_before():
            Skript.error("Can't change the protocol version anymore after the server list ping event has already passed")
            return None
        elif mode == ChangeMode.SET:
            return [Number]
        return None

    def change(self, e: Event, delta: List[Object], mode: ChangeMode) -> None:
        (PaperServerListPingEvent(e)).set_protocol_version(int(delta[0]))

    def is_single(self) -> bool:
        return True

    def get_return_type(self) -> Class[List[Long]]:
        return Long

    def to_string(self, e: Event, debug: bool) -> str:
        return "the protocol version"
```

Please note that Python does not support Java-like annotations or docstrings. The `@` symbol is used for decorators in Python and has a different meaning than it does in Java.