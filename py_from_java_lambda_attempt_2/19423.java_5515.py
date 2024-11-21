Here is the translation of the given Java code into Python:

```Python
class SheepData:
    def __init__(self):
        self.colors = None
        self.sheared = 0

    @staticmethod
    def register():
        EntityData.register(SheepData, "sheep", Sheep, 1, "unsheared sheep", "sheep", "sheared sheep")

    def init(self, exprs: list[Literal], matched_pattern: int, parse_result: ParseResult) -> bool:
        self.sheared = matched_pattern - 1
        if exprs[0] is not None:
            self.colors = [(expr) for expr in (exprs[0]).getAll()]
        return True

    def init(self, c: Class[Sheep], e: Sheep) -> bool:
        if e is not None:
            self.sheared = 1 if e.isSheared() else -1
            self.colors = [SkriptColor.fromDyeColor(e.getColor())]
        return True

    def set(self, entity: Sheep):
        if self.colors is not None:
            c = random.choice(self.colors)
            assert c is not None
            entity.setColor(c.asDyeColor())

    def match(self, entity: Sheep) -> bool:
        return (self.sheared == 0 or entity.isSheared() == (self.sheared == 1)) and \
               ((self.colors is None) or SimpleExpression.check(self.colors, lambda c: entity.getColor() == c.asDyeColor(), False, False))

    def get_type(self):
        return Sheep

    @property
    def adjectives(self):
        if self._adjectives is not None:
            return self._adjectives
        else:
            self._adjectives = [Adjective] * len(self.colors)
            for i in range(len(self.colors)):
                if isinstance(self.colors[i], SkriptColor):
                    self._adjectives[i] = (self.colors[i]).getAdjective()
            return self._adjectives

    def __str__(self, flags: int) -> str:
        name = self.get_name()
        age = self.get_age_adjective()
        if self.colors is None:
            return super().__str__(flags)
        adjs = self.adjectives
        result = f"{name.article_with_space(flags)} " + ("" if age is None else f"{age.toString(name.gender(), flags)} ") + \
                 Adjective.toString(adjs, name.gender(), flags, False) + " " + name.toString(flags & Language.NO_ARTICLE_MASK)
        return result

    def __hash__(self):
        prime = 31
        hash_value = 1
        if self.colors is not None:
            for color in self.colors:
                hash_value = (prime * hash_value) ^ hash(color.name())
        hash_value = (prime * hash_value) + self.sheared
        return hash_value

    def __eq__(self, other):
        if isinstance(other, SheepData):
            if not array_equal(self.colors, other.colors):
                return False
            if self.sheared != other.sheared:
                return False
            return True
        else:
            return False

#   def to_string(self) -> str:
#       if self.colors is None:
#           return f"{self.sheared}"
#       else:
#           result = f"{self.sheared}|"
#           for color in self.colors:
#               if len(result) != 0:
#                   result += ","
#               result += color.name()
#           return result

    def deserialize(self, s: str):
        split = s.split("|")
        sh = split[0]
        if len(split) == 1:
            return False
        elif len(split) == 2:
            colors_str = split[1].split(",")
            self.colors = [SkriptColor.valueOf(c) for c in colors_str]
            return True
        else:
            return False

    def is_supertype_of(self, e: EntityData):
        if isinstance(e, SheepData):
            return (self.colors is None or CollectionUtils.is_subset(self.colors, e.colors))
        return False

    @property
    def super_type(self) -> EntityData:
        return self.__class__()
```

Note that this translation assumes the existence of certain classes and methods (`Literal`, `ParseResult`, `Sheep`, etc.) which are not defined in the given Java code.