Here is the translation of the given Java code into Python:

```Python
class ColorSelector:
    def __init__(self, target_color):
        self.target_color = target_color

    def test(self, creature):
        return creature.color == self.target_color


def test_color():
    green_creature = {"color": "GREEN"}
    red_creature = {"color": "RED"}

    green_selector = ColorSelector("GREEN")
    assert green_selector.test(green_creature) is True
    assert green_selector.test(red_creature) is False


if __name__ == "__main__":
    test_color()
```

This Python code defines a `ColorSelector` class that takes a target color in its constructor. The `test` method of this class checks if the given creature's color matches the target color.

The `test_color` function creates two creatures with different colors and uses these to test the `ColorSelector`.