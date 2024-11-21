Here is a translation of the Java code into equivalent Python:

```Python
class LocationVectorOffset:
    def __init__(self):
        self.location = None
        self.vectors = None

    @staticmethod
    def register_expression():
        pass  # Skript.registerExpression(ExprLocationVectorOffset, Location, ExpressionType.SIMPLE, "%location% offset by [[the] vectors]%vectors%", "%location%[ ]~[~][ ]%vectors%")

    def init(self, exprs):
        self.location = exprs[0]
        self.vectors = exprs[1]
        return True

    def get(self, e):
        l = self.location.get(e)
        if l is None:
            return None
        clone = l.clone()
        for v in self.vectors.get(e):
            clone.add(v)
        return [clone]

    @property
    def is_single(self):
        return True

    @property
    def get_return_type(self):
        return Location  # Class<? extends Location>

    def __str__(self, e=None, debug=False):
        if not isinstance(debug, bool) or not debug:
            return f"{self.location} offset by {self.vectors}"
```

Please note that Python does not have direct equivalent of Java's static blocks and annotations.