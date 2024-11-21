class TeleportCauseExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Teleport Cause"

    @property
    def description(self):
        return ("The teleport cause within a player teleport event."
                "<a href='classes.html#teleportcause'>teleport cause</a>")

    @property
    def examples(self):
        return ["on teleport",
                "\tteleport cause is nether portal, end portal or end gateway"]

    @property
    def since(self):
        return "2.2-dev35"

def register_expression():
    pass

class EventValueExpression:
    def __init__(self, event_type):
        self.event_type = event_type

    def to_string(self, e, debug=False):
        if not isinstance(e, dict) or 'event' not in e:
            return "the teleport cause"
