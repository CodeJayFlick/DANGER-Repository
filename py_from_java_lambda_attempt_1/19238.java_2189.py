Here is the translation of the given Java code into Python:

```Python
class CondIncendiary:
    def __init__(self):
        self.is_event = None
        self.entities = None

    @staticmethod
    def register_condition():
        Skript.register_condition(CondIncendiary, "%entities%  ((is|are) incendiary|cause[s] a[ n] (incendiary|fiery) explosion)",
                                 "%entities%  ((is not|are not| isn't|aren't) incendiary|(does not|do not|doesn't|don't) cause[s] a[n] (incendiary|fiery) explosion)",
                                 "the [event(-| )explosion (is|1¦(is not| isn't)) (incendiary|fiery)")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.is_event = matched_pattern == 2
        if self.is_event and not Skript.get_parser().is_current_event("org.bukkit.event.entity.ExplosionPrimeEvent"):
            Skript.error("Checking if 'the explosion' is fiery is only possible in an explosion prime event", ErrorQuality.SEMANTIC_ERROR)
            return False

        if not self.is_event:
            self.entities = exprs[0]

        self.set_negated(matched_pattern == 1 or parse_result.mark == 1)

    def check(self, e):
        if self.is_event:
            return ((e.get("org.bukkit.event.entity.ExplosionPrimeEvent")).get_fire() ^ not self.negated())
        return self.entities.check(e, lambda entity: isinstance(entity, "org.bukkit.entity.Exploding") and (entity).is_incendiary(), not self.negated())

    def __str__(self, e=None, debug=False):
        if self.is_event:
            return f"the event-explosion {(' is' if not self.negated() else ' is not') } incendiary"
        if self.entities.single():
            return f"{self.entities} {'is' if not self.negated() else 'is not'} incendiary"
        return f"{self.entities} {'are' if not self.negated() else ' are not'} incendiary"

# Usage
CondIncendiary.register_condition()
```

Please note that this translation is based on the assumption that `Skript`, `ErrorQuality` and other classes/objects are available in Python.