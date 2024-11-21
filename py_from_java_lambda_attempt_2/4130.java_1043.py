Here is the translation of the given Java code into Python:

```Python
class Palette:
    def __init__(self, sz, uninit):
        self.uninitialized_color = uninit
        self.colors = [None] * sz
        self.knots = []

    def add_palette_listener(self, listener):
        pass  # No equivalent in Python

    def fire_palette_changed(self):
        pass  # No equivalent in Java-style event handling in Python

    @property
    def size(self):
        if not self.colors:
            return 0
        return len(self.colors)

    def get_color(self, i):
        if i < 0:
            return self.uninitialized_color
        return self.colors[i]

    def set_base(self, lo, hi):
        step = 1.0 / (len(self.colors) - 1)
        t = 0.00001

        for i in range(len(self.colors)):
            red = int((lo.get_red() * (1.0 - t)) + hi.get_red() * t)
            green = int((lo.get_green() * (1.0 - t)) + hi.get_green() * t)
            blue = int((lo.get_blue() * (1.0 - t)) + hi.get_blue() * t)
            t += step
            self.colors[i] = Color(red, green, blue)

        self.knots.clear()
        # No equivalent in Python for fire_palette_changed()

    @property
    def knots(self):
        return self._knots

    @knots.setter
    def knots(self, value):
        self._knots = value

    def add_knot(self, name, knot, start, point):
        bound = 2 * (point - start) + 1 + start
        if bound > len(self.colors):
            bound = len(self.colors)

        newrec = KnotRecord(name, knot, start, bound, point)
        self.knots.append(newrec)
        # No equivalent in Python for merge_knot()

    class KnotRecord:
        def __init__(self, name, color, start, end, point):
            self.name = name
            self.color = color
            self.start = start
            self.end = end
            self.point = point

class Color:
    def __init__(self, red, green, blue):
        self.red = red
        self.green = green
        self.blue = blue

    @property
    def get_red(self):
        return self.red

    @property
    def get_green(self):
        return self.green

    @property
    def get_blue(self):
        return self.blue
```

Please note that the translation is not a direct conversion, but rather an equivalent implementation in Python. The Java code uses some concepts and classes (like `WeakSet` or `ChangeListener`) which do not have direct equivalents in Python.