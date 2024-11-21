Here's a translation of your Java code into Python:

```Python
class CondIsLoaded:
    def __init__(self):
        self.locations = None
        self.x = None
        self.z = None
        self.world = None
        self.pattern = 0

    @staticmethod
    def register_condition():
        Skript.register_condition(CondIsLoaded, "chunk[es] %directions% [%locations%] (is|are)[1¦not ] loaded",
                                 "chunk [at] %number%, %number% (in|of) [world] %world% is[(1¦not )] loaded",
                                 "[world[s]] %worlds% (is|are)[1¦not ] loaded")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.pattern = matched_pattern
        if self.pattern == 0:
            self.locations = Direction.combine(exprs[0], exprs[1])
        elif self.pattern in [1, 2]:
            if self.pattern == 1:
                self.x = exprs[0]
                self.z = exprs[1]
                self.world = None
            else:
                self.world = exprs[0]
                self.x = None
                self.z = None
        set_negated(parse_result.mark == 1)
        return True

    def check(self, e):
        if self.pattern == 0:
            return self.locations.check(e, lambda location: World(location.get_world()).is_chunk_loaded(location.get_block_x() >> 4, location.get_block_z() >> 4) != is_negated())
        elif self.pattern in [1, 2]:
            world = self.world
            if self.pattern == 1:
                x = self.x.get_single(e)
                z = self.z.get_single(e)
                return world.is_chunk_loaded(x, z) if (x and z) else False
            else:
                return Bukkit.get_world(world).is_chunk_loaded() != is_negated()
        return False

    def __str__(self, e, d):
        neg = " not " if self.is_negated() else ""
        chunk = f"chunk[es] at {self.locations} {'are' if self.locations.is_single() else ' '}loaded{neg}" if self.pattern == 0 \
               else (f"world[s] {self.world} {'is' if self.world.is_single() else ' '}loaded{neg}" if self.pattern == 2 \
                     else f"chunk x:{self.x}, z:{self.z}, w:{self.world} is{' not ' if self.is_negated() else ''} loaded")
        return chunk
```

Note that this translation assumes you have a `Direction` class and the necessary methods for combining directions, getting block coordinates from locations, etc. You may need to modify or add these classes depending on your specific use case.

Also note that Python does not support static initialization blocks like Java does. Instead, we can define an initializer method (`__init__`) in our `CondIsLoaded` class and call it manually when needed.