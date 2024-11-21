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
