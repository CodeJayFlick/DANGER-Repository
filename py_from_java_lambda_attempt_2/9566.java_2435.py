Here is the translation of the Java code to Python:
```
class EmptyFieldBackgroundColorManager:
    EMPTY_INSTANCE = None
    EMPTY_HIGHLIGHT_LIST = []

    def __init__(self):
        pass

    def get_selection_highlights(self, row: int) -> list:
        return self.EMPTY_HIGHLIGHT_LIST

    def get_background_color(self) -> tuple:
        return (0, 0, 0, 0)

    def get_padding_color(self, pad_index: int) -> tuple:
        return (0, 0, 0, 0)
```
Note that I've used the following Python concepts to translate the Java code:

* Classes and objects are defined using the `class` keyword.
* Methods are defined inside classes using indentation.
* The `return` statement is used to specify the value returned by a method.
* Tuples (similar to Java's `Color`) are used to represent colors, with four values for RGB and alpha channels.