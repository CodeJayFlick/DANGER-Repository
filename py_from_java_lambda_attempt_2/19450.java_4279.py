Here is the translation of the given Java code into Python:

```Python
class EvtEntity:
    def __init__(self):
        self.types = None
        self.spawn = False

    @staticmethod
    def register_events():
        Skript.register_event("Death", EvtEntity, EntityDeathEvent, "death [of %entitydatas%]")
        Skript.event_description("Called when a living entity (including players) dies.")
        Skript.add_examples(["on death:", "on death of player:", "on death of a wither or ender dragon:",
                             "    broadcast \"A %%entity%% has been slain in %%world%!\""])
        Skript.set_since_version("1.0")

        Skript.register_event("Spawn", EvtEntity, EntitySpawnEvent, "spawn [of %entitydatas%]")
        Skript.event_description("Called when an entity spawns (excluding players).")
        Skript.add_examples(["on spawn of a zombie:", "on spawn of an ender dragon:",
                             "    broadcast \"A dragon has been sighted in %%world%!\""])
        Skript.set_since_version("1.0, 2.5.1 (non-living entities)")

    def init(self, args, matched_pattern, parser):
        self.types = None if args[0] is None else [d for d in ((Literal(args[0])).getAll())]
        self.spawn = parser.expr.startswith('spawn', ignore_case=True)
        if self.types:
            if self.spawn:
                for d in self.types:
                    if isinstance(d.getType(), HumanEntity):
                        Skript.error("The spawn event does not work for human entities", ErrorQuality.SEMANTIC_ERROR)
                        return False
            else:
                for d in self.types:
                    if not isinstance(d.getType(), LivingEntity):
                        Skript.error("The death event only works for living entities", ErrorQuality.SEMANTIC_ERROR)
                        return False

    def check(self, e):
        if self.types is None:
            return True
        en = e.get_entity() if isinstance(e, EntityDeathEvent) else ((EntitySpawnEvent)e).get_entity()
        for d in self.types:
            if d.is_instance(en):
                return True
        return False

    def __str__(self, e=None, debug=False):
        return f"{'spawn' if self.spawn else 'death'} {' of ' + str(self.types) if self.types is not None else ''}"
```

Note: This code assumes that you have a `Skript` class with methods like `register_event`, `event_description`, `add_examples`, and `set_since_version`. Similarly, it also assumes the existence of classes like `EntityDeathEvent`, `EntitySpawnEvent`, `HumanEntity`, and `LivingEntity`.