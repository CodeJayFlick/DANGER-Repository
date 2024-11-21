Here is a translation of the Java code into Python:

```Python
class LightLevel:
    def __init__(self):
        self.SKY = 1
        self.BLOCK = 2
        self.ANY = self.SKY | self.BLOCK
        self.what_light = self.ANY

    @property
    def description(self):
        return {"Gets the light level at a certain location which ranges from 0 to 15.",
                "It can be separated into sunlight (15 = direct sunlight, 1-14 = indirect) and block light (torches, glowstone, etc.). The total light level of a block is the maximum of the two different light types."}

    @property
    def examples(self):
        return [{"# set vampire players standing in bright sunlight on fire",
                "every 5 seconds:",
                "	loop all players:",
                "	{vampire::%uuid of loop-player%} is true",
                "	sunlight level at the loop-player is greater than 10",
                "	ignite the loop-player for 5 seconds"}]

    @property
    def since(self):
        return "1.3.4"

    def register_expression(cls, expression_type="[(1¦sky|1¦sun|2¦block)[ ]light[ ]level [(of|%direction%) %location%]]"):
        Skript.register_expression(expression_type)

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.set_expr(Direction.combine(exprs[0], exprs[1]))
        self.what_light = parse_result.mark == 0 and self.ANY or parse_result.mark
        return True

    @property
    def get_return_type(cls):
        return Byte

    def get(self, e, source):
        converter = Converter()
        result = []
        for location in source:
            block = location.get_block()
            if self.what_light == self.ANY:
                light_level = block.get_light_level()
            elif self.what_light == self.BLOCK:
                light_level = block.get_light_from_blocks()
            else:
                light_level = block.get_light_from_sky()
            result.append(converter.convert(location))
        return result

    def __str__(self, e=None, debug=False):
        if self.what_light == self.BLOCK:
            prefix = "block "
        elif self.what_light == self.SKY:
            prefix = "sky "
        else:
            prefix = ""
        return f"{prefix}light level {self.get_expr()}"
```

Please note that Python does not support Java-like features such as annotations (`@Name`, `@Description`, etc.) or static initialization blocks. The equivalent functionality is achieved through the use of properties and methods in this translation.