Here is the translation of the given Java code into Python:

```Python
class IsBlockRedstonePowered:
    def __init__(self):
        self.blocks = None
        self.is_indirectly_powered = False

    @property
    def description(self):
        return "Checks if a block is indirectly or directly powered by redstone"

    @property
    def examples(self):
        return [
            {"if clicked block is redstone powered:",
             "send \"This block is well-powered by redstone!\""},
            {"if clicked block is indirectly redstone powered:",
             "send \"This block is indirectly redstone powered.\""}
        ]

    @property
    def since(self):
        return "2.5"

    def register_condition(cls, patterns):
        Skript.register_condition(IsBlockRedstonePowered, *patterns)

IsBlockRedstonePowered.register_condition([
    "%blocks% (is|are) redstone powered",
    "%blocks% (is|are) indirectly redstone powered",
    "%blocks% (is|are)(n' t| not) redstone powered",
    "%blocks% (is|are)(n' t| not) indirectly redstone powered"
])

def init(self, exprs):
    self.blocks = exprs[0]
    if len(exprs) > 1:
        self.is_indirectly_powered = bool(int(exprs[1]))
    else:
        self.is_indirectly_powered = True
    return not (len(exprs) == 2 and int(exprs[1]) != 0)

def check(self, e):
    if self.is_indirectly_powered:
        return self.blocks.check(e, lambda x: x.is_block_indirectly_powered(), not self.negated())
    else:
        return self.blocks.check(e, lambda x: x.is_block_powered(), not self.negated())

def __str__(self, e=None, debug=False):
    if e is None and debug:
        return f"IsBlockRedstonePowered({self.blocks}, {'' if not self.is_indirectly_powered else 'indirectly '}powered)"
    elif e is None or not debug:
        return "IsBlockRedstonePowered"
```

This Python code defines a class `IsBlockRedstonePowered` that has methods for initializing, checking and string representation. The `register_condition` function registers the condition with Skript.