Here is the translation of the given Java code into Python:

```Python
class ToggleFlight:
    def __init__(self):
        self.players = None
        self.allow = False

    @staticmethod
    def register_effect():
        Skript.register_effect(ToggleFlight, "(allow|enable) (fly|flight) (for|to) %players%", "(disallow|disable) (fly|flight) (for|to) %players%")

    def init(self, exprs, matched_pattern):
        self.players = exprs[0]
        self.allow = matched_pattern == 0
        return True

    def execute(self, e):
        for player in self.players.get_array(e):
            player.set_allow_flight(self.allow)

    def __str__(self, e=None, debug=False):
        if not e:
            return "allow flight to {}".format(str(self.players))
        else:
            return str(self.players)
```

Please note that this is a direct translation of the Java code into Python. The equivalent functionality in Python might be slightly different due to differences between languages (e.g., static vs instance methods, etc.).