class LastLoadedServerIcon:
    def __init__(self):
        self.PAPER_EVENT_EXISTS = hasattr('com.destroystokyo.paper.event.server', 'PaperServerListPingEvent')

    @property
    def description(self):
        return "Returns the last loaded server icon with the load server icon effect."

    @property
    def examples(self):
        return ["set {server-icon} to the last loaded server icon"]

    @property
    def since(self):
        return "2.3"

    @property
    def required_plugins(self):
        return ['Paper 1.12.2 or newer']

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.PAPER_EVENT_EXISTS:
            print("The last loaded server icon expression requires Paper 1.12.2+")
            return False
        return True

    def get(self, e=None):
        from ch.njol.skript.effects import EffLoadServerIcon
        return [EffLoadServerIcon.lastLoaded]

    @property
    def is_single(self):
        return True

    @property
    def return_type(self):
        from org.bukkit.util import CachedServerIcon
        return CachedServerIcon

    def __str__(self, e=None, debug=False):
        if not debug:
            return "the last loaded server icon"
