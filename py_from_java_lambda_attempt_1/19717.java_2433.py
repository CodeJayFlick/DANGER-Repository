Here is the translation of the given Java code into Python:

```Python
class VectorFromXYZ:
    def __init__(self):
        self.x = None
        self.y = None
        self.z = None

    @property
    def description(self):
        return "Creates a vector from x, y and z values."

    @property
    def examples(self):
        return ["set {_v} to vector 0, 1, 0"]

    @property
    def since(self):
        return "2.2-dev28"

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.x = exprs[0]
        self.y = exprs[1]
        self.z = exprs[2]
        return True

    def get(self, e):
        x = self.x.get_single(e)
        y = self.y.get_single(e)
        z = self.z.get_single(e)

        if x is None or y is None or z is None:
            return None
        else:
            return [Vector(x.double_value(), y.double_value(), z.double_value())]

    def is_single(self):
        return True

    def get_return_type(self):
        from vector import Vector  # Assuming you have a Vector class defined elsewhere in your codebase.
        return Vector

    def __str__(self, e=None, debug=False):
        if not isinstance(e, dict):  # If 'e' is None or False
            e = {}
        if not isinstance(debug, bool):
            debug = False

        return f"vector from x {self.x.__str__(e, debug)}, y {self.y.__str__(e, debug)}, z {self.z.__str__(e, debug)}"
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations. These are used for documentation purposes and can be replaced with docstrings in Python.

Also, the Vector class is assumed to exist elsewhere in your codebase. If you don't have a Vector class defined, you would need to implement it or use an existing one that fits your needs.