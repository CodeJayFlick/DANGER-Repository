Here is a translation of the Java code into equivalent Python:

```Python
class BiomeExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Biome"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return """The biome at a certain location. Please note that biomes are only defined for x/z-columns, i.e. the altitude (y-coordinate) doesn't matter."""

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["# damage player in deserts constantly", "every real minute:", "loop all players:", "biome at loop-player is desert", "damage the loop-player by 1"]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "1.4.4"

    @since.setter
    def since(self, value):
        self._since = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if matched_pattern == 1:
            location_expr = exprs[0]
        else:
            direction_expr = exprs[0]
            location_expr = Direction.combine(direction_expr, exprs[1])
        self.set_expr(location_expr)
        return True

    def get(self, e, source):
        biomes = []
        for l in source:
            biome = l.get_world().get_biome(l.get_block_x(), l.get_block_z())
            biomes.append(biome)
        return biomes

    def accept_change(self, mode):
        if mode == "set":
            return [Biome]
        else:
            return super.accept_change(mode)

    def change(self, e, delta, mode):
        if mode == "set":
            biome = delta[0]
            for l in self.get_expr().get_array(e):
                l.get_world().set_biome(l.get_block_x(), l.get_block_z(), biome)
        else:
            super.change(e, delta, mode)

    def get_return_type(self):
        return Biome

    def __str__(self, e=None, debug=False):
        if not e and not debug:
            return "the biome at %s" % self.get_expr()
        elif not e and debug:
            return "BiomeExpression: the biome at %s" % self.get_expr()
        else:
            return "the biome at %s during event %s" % (self.get_expr(), str(e))
```

Note that this is a direct translation of your Java code into Python, without any attempt to optimize or improve it.