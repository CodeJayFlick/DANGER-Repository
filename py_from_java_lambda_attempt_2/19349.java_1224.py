Here is a translation of the Java code into Python:

```Python
import time
from datetime import timedelta

class EffIgnite:
    def __init__(self):
        self.entities = None
        self.ignite = False
        self.duration = None

    @staticmethod
    def register_effect():
        Skript.register_effect(EffIgnite, "ignite %entities% [for %-timespan%]", "set %entities% on fire [for %-timespan%]", "extinguish %entities%")

    def init(self, exprs):
        self.entities = exprs[0]
        if len(exprs) > 1:
            self.ignite = True
            self.duration = exprs[1]

    def execute(self, e):
        d = DEFAULT_DURATION if not self.duration else int(timedelta(seconds=self.duration.get_single(e)).total_seconds())
        for en in self.entities.get_array(e):
            if isinstance(e, EntityDamageEvent) and ((EntityDamageEvent)e).get_entity() == en:
                time.sleep(d)
                en.set_fire_ticks(d)
            elif isinstance(e, EntityCombustEvent) and ((EntityCombustEvent)e).get_entity() == en:
                (EntityCombustEvent)e.set_cancelled(True)

    def __str__(self):
        if self.ignite:
            return f"set {self.entities} on fire for {timedelta(seconds=DEFAULT_DURATION)}"
        else:
            return f"extinguish {self.entities}"

# usage
eff_ignite = EffIgnite()
eff_ignite.init(["player", "10 seconds"])
eff_ignite.execute("entity_damage_event")
print(eff_ignite)
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect.