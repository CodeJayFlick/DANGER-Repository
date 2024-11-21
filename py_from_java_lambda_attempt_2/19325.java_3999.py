Here is the translation of the given Java code into Python:

```Python
class BreakBlock:
    def __init__(self):
        self.blocks = None
        self.tool = None

    @property
    def blocks(self):
        return self._blocks

    @blocks.setter
    def blocks(self, value):
        self._blocks = value

    @property
    def tool(self):
        return self._tool

    @tool.setter
    def tool(self, value):
        self._tool = value

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if len(exprs) >= 2:
            self.blocks = exprs[0]
            self.tool = exprs[1]
        return True

    def execute(self, e):
        tool = self.tool.get() if self.tool else None
        for block in self.blocks.get():
            if tool:
                item_stack = tool.get_random()
                if item_stack is not None:
                    block.break_naturally(item_stack)
                else:
                    block.break_naturally()
            else:
                block.break_natural()

    def __str__(self, e=None, debug=False):
        return f"break {self.blocks} naturally{'' if self.tool is None else f' using {self.tool}'}"
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations. These are used for documentation purposes and can be achieved in Python by adding docstrings to the functions or classes.