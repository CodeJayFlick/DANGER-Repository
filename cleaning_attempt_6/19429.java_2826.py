class WolfData:
    def __init__(self):
        self._register()

    def _register(self):
        from ch.njol.skript.lang import Literal
        from org.bukkit.entity import Wolf
        EntityData.register(WolfData, "wolf", Wolf, 1,
                            "angry wolf", "wolf", "peaceful wolf",
                            "wild wolf", "tamed wolf")

    def __init__(self):
        self.angry = 0
        self.tamed = 0

    @property
    def angry(self):
        return self._angry

    @angry.setter
    def angry(self, value):
        if isinstance(value, int) and (value == -1 or value == 0 or value == 1):
            self._angry = value
        else:
            raise ValueError("Invalid value for 'angry'")

    @property
    def tamed(self):
        return self._tamed

    @tamed.setter
    def tamed(self, value):
        if isinstance(value, int) and (value == -1 or value == 0 or value == 1):
            self._tamed = value
        else:
            raise ValueError("Invalid value for 'tamed'")

    def init(self, exprs: list[Literal], matched_pattern: int, parse_result: ParseResult) -> bool:
        if matched_pattern <= 2:
            self.angry = matched_pattern - 1
        elif matched_pattern == 3:
            self.tamed = -1
        else:
            self.tamed = 1
        return True

    def init(self, c: type[Wolf], e: Wolf) -> bool:
        if e is None:
            self.angry = 0
            self.tamed = 0
        elif not e.isAngry():
            self.angry = -1
        else:
            self.angry = 1

        if not e.isTamed():
            self.tamed = -1
        else:
            self.tamed = 1
        return True

    def set(self, entity: Wolf) -> None:
        if self.angry != 0:
            entity.setAngry(self.angry == 1)
        if self.tamed != 0:
            entity.setTamed(self.tamed == 1)

    def match(self, entity: Wolf) -> bool:
        return (self.angry == 0 or entity.isAngry() == (self.angry == 1)) and \
               (self.tamed == 0 or entity.isTamed() == (self.tamed == 1))

    @property
    def type(self):
        from org.bukkit.entity import Wolf
        return Wolf

# This part is not present in the original Java code, so I'm assuming it's a mistake.
