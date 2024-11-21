Here is the translation of the Java code to Python:
```
class ParticleOption:
    def __init__(self, color: tuple, size: float):
        self.color = Color.from_bukkit_color(color)
        self.size = size

    @property
    def bukkit_color(self) -> tuple:
        return self.color

    @property
    def red(self) -> float:
        return self.color[0] / 255.0

    @property
    def green(self) -> float:
        return self.color[1] / 255.0

    @property
    def blue(self) -> float:
        return self.color[2] / 255.0

    def __str__(self):
        return f"ParticleOption{{color={self.color}, size={self.size}}}"
```
Note that I've used the `@property` decorator to create read-only properties for the color, red, green, and blue attributes. This is equivalent to the getter methods in Java.

I've also assumed that you have a `Color` class with an `as_bukkit_color()` method, which returns a tuple representing the Bukkit color (e.g., `(255, 0, 0)` for red). You'll need to implement this class separately.