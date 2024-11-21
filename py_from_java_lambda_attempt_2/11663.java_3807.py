Here is the translation of the given Java code into Python:

```Python
class ParserWalkerChange:
    def __init__(self, context):
        self.context = context

    def get_parser_context(self):
        return self.context

    @property
    def point(self):
        pass  # This attribute seems to be missing in the original Java class.

    def set_offset(self, off):
        if hasattr(self.point, 'offset'):
            self.point.offset = off

    def set_constructor(self, c):
        if hasattr(self.point, 'ct'):
            self.point.ct = c

    def set_current_length(self, len):
        if hasattr(self.point, 'length'):
            self.point.length = len

    def calc_current_length(self, length, numopers):
        # Calculate the length of the current constructor state assuming all its operands are constructed
        length += self.point.offset  # Convert relative length to absolute length
        for i in range(numopers):
            subpoint = getattr(self.point.resolve, f'get({i})')
            sublength = subpoint.length + subpoint.offset
            if sublength > length:
                length = sublength
        self.point.length = length - self.point.offset  # Convert back to relative length

# Example usage:
context = 'some context'
walker_change = ParserWalkerChange(context)
print(walker_change.get_parser_context())
```

Please note that the `point` attribute seems to be missing in the original Java class, so I left it as a placeholder. Also, Python does not have direct equivalent of Java's constructor concept, but we can achieve similar functionality using an initializer method (`__init__`).