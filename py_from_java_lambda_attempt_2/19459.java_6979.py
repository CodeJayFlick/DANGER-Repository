Here is the equivalent Python code:

```Python
class EvtLevel:
    def __init__(self):
        self.leveling = None

    @staticmethod
    def register_event():
        Skript.register_event("Level Change", EvtLevel, PlayerLevelChangeEvent, "[player] level (change|1¦up|-1¦down)")
        Skript.description("Called when a player's <a href='expressions.html#ExprLevel'>level</a> changes, e.g. by gathering experience or by enchanting something.")
        Skript.examples(["on level change:"])
        Skript.since("1.0, 2.4 (level up/down)")

    def init(self, args, matched_pattern):
        self.leveling = Kleenean.get(matched_pattern)
        return True

    def check(self, event):
        if self.leveling:
            return event.new_level > event.old_level
        elif not self.leveling:
            return event.new_level < event.old_level
        else:
            return True

    def __str__(self, e=None, debug=False):
        return f"level {('up' if self.leveling else 'down' if not self.leveling else 'change')}"
```

Note that Python does not have direct equivalent of Java's static blocks or annotations. Also, the `Kleenean` class is not present in this translation as it seems to be a custom utility class used in Skript.