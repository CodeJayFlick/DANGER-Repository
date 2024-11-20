Here is the translation of the Java code to Python:
```
class EmptyLayoutBackgroundColorManager:
    def __init__(self, background: tuple):
        self.background = color(*background)

    def get_field_background_color_manager(self, field_num: int) -> 'EmptyFieldBackgroundColorManager':
        return EmptyFieldBackgroundColorManager.EMPTY_INSTANCE

    def get_background_color(self) -> tuple:
        return self.background

    def get_padding_color(self, gap: int) -> None:
        pass  # equivalent to returning null in Java

    def get_background_color_for_location(self, location: 'FieldLocation') -> tuple:
        return self.background
```
Note that I used the `color` function from the `tkinter` module (which is part of Python's standard library) to create a color object. This is equivalent to creating a `Color` object in Java.

I also replaced the `public` access modifier with nothing, as Python does not have explicit access modifiers like Java does.

Additionally, I used type hints for function parameters and return types, which are optional but can be useful for documentation purposes.