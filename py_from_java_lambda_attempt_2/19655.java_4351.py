Here is a translation of the given Java code into equivalent Python:

```Python
class PotionEffectExpression:
    def __init__(self):
        self.potion_effect_type = None
        self.tier = None
        self.timespan = None
        self.particles = True
        self.ambient = False

    @property
    def pattern(self):
        return r"[new] potion effect of %potioneffecttype% [potion] [[of tier]] %-number%] [(1¦without particles)] [for %-timespan%]"

    @property
    def delayed_pattern(self):
        return self.pattern

    def init(self, exprs: list, matched_pattern: int) -> bool:
        if len(exprs) != 3:
            raise ValueError("Invalid number of expressions")
        
        self.potion_effect_type = exprs[0]
        self.tier = exprs[1]
        self.timespan = exprs[2]

        if matched_pattern == 0:
            self.particles = True
        else:
            self.ambient = True

        return True

    def get(self, e):
        potion_effect_type = self.potion_effect_type.get(e)
        
        if potion_effect_type is None:
            return []

        tier = 1
        if self.tier is not None and isinstance(self.tier, int):
            tier = self.tier
        
        ticks = 300  # default potion length in seconds

        if self.timespan is not None and isinstance(self.timespan, int):
            ticks = self.timespan
        
        return [PotionEffect(potion_effect_type, ticks, tier - 1, self.ambient, self.particles)]

    def is_single(self) -> bool:
        return True


class PotionEffect:
    def __init__(self, potion_effect_type: str, duration: int, amplifier: int, ambient: bool, particles: bool):
        self.potion_effect_type = potion_effect_type
        self.duration = duration
        self.amplifier = amplifier
        self.ambient = ambient
        self.particles = particles


class PotionEffectType:
    def __init__(self, name: str):
        self.name = name

    @property
    def get(self, e) -> str:
        return self.name

```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations for documentation purposes.