Here is the translation of the given Java code into Python:

```Python
import random

class TropicalFishData:
    def __init__(self):
        self.matched_pattern = 0
        self.body_color = None
        self.pattern_color = None

    @staticmethod
    def register():
        if Skript.is_running_minecraft(1, 13):
            patterns = [Pattern.values()]
            TropicalFishData.register("tropical fish", "kob", "sunstreak", "snooper",
                                       "dasher", "brinely", "spotty", "flopper",
                                       "stripey", "glitter", "blockfish", "betty", "clayfish")

    def __init__(self, pattern):
        self.matched_pattern = pattern

    @property
    def matched_pattern(self):
        return self._matched_pattern

    @matched_pattern.setter
    def matched_pattern(self, value):
        if isinstance(value, int) and 0 <= value <= len(patterns):
            self._matched_pattern = value
        else:
            raise ValueError("Invalid pattern")

    @property
    def body_color(self):
        return self._body_color

    @body_color.setter
    def body_color(self, color):
        if isinstance(color, DyeColor):
            self._body_color = color
        elif color is None or isinstance(color, str) and color.lower() in ["white", "black"]:
            self._body_color = DyeColor.WHITE if color == "white" else DyeColor.BLACK
        else:
            raise ValueError("Invalid body color")

    @property
    def pattern_color(self):
        return self._pattern_color

    @pattern_color.setter
    def pattern_color(self, color):
        if isinstance(color, DyeColor) and color != self.body_color:
            self._pattern_color = color
        elif color is None or isinstance(color, str) and color.lower() in ["white", "black"]:
            self._pattern_color = DyeColor.WHITE if color == "white" else DyeColor.BLACK
        else:
            raise ValueError("Invalid pattern color")

    def init(self, exprs):
        if len(exprs) > 0:
            for i, expr in enumerate(exprs):
                if isinstance(expr, Literal):
                    if i < 2 and expr.get_single().as_dye_color() is not None:
                        self.body_color = expr.get_single().as_dye_color()
                    elif i == 1 or (i >= 3 and len(exprs) > 3):
                        self.pattern_color = expr.get_single().as_dye_color()

    def set(self, entity):
        if self.matched_pattern != 0:
            entity.set_pattern(patterns[self.matched_pattern - 1])
        else:
            entity.set_pattern(random.choice(patterns))
        if self.body_color is not None:
            entity.set_body_color(self.body_color)
        if self.pattern_color is not None and self.pattern_color != self.body_color:
            entity.set_pattern_color(self.pattern_color)

    def match(self, entity):
        same_pattern = self.matched_pattern == 0 or self.matched_pattern == entity.get_pattern().ordinal()
        same_body = self.body_color is None or self.body_color == entity.get_body_color()

        if self.pattern_color is not None:
            return same_pattern and same_body and self.pattern_color == entity.get_pattern_color()
        else:
            return same_pattern and same_body

    def get_type(self):
        return TropicalFish
```

Please note that Python does not support Java's `@Nullable` annotation.