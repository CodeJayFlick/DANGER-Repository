Here is the translation of the Java code to Python:
```
class TranslateIcon:
    def __init__(self, icon: 'Icon', translate_x: int, translate_y: int):
        self.icon = icon
        self.translate_x = translate_x
        self.translate_y = translate_y

    def paint_icon(self, c: object, g: object, x: int, y: int) -> None:
        self.icon.paint_icon(c, g, x + self.translate_x, y + self.translate_y)

    @property
    def icon_height(self) -> int:
        return self.icon.get_icon_height()

    @property
    def icon_width(self) -> int:
        return self.icon.get_icon_width()

    def __str__(self) -> str:
        return f"{type(self).__name__} [{ResourceManager.get_icon_name(self.icon)}]"
```
Note that I've used type hints for the `icon` parameter in the constructor, as well as for the method parameters and return types. This is not strictly necessary, but it can help with code readability and static analysis.

Also, I've assumed that there is a separate class or module called `ResourceManager` that has a method `get_icon_name(icon: 'Icon') -> str`. You will need to define this class or module separately in your Python code.