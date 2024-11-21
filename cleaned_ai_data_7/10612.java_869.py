class EmptyIcon:
    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height

    @property
    def icon_height(self) -> int:
        return self.height

    @property
    def icon_width(self) -> int:
        return self.width

    def paint_icon(self, c=None, g=None, x=0, y=0):
        pass  # no-op
