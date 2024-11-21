Here's your Java code translated into Python:

```Python
class AttributedString:
    UNDERLINE_HEIGHT = 1

    def __init__(self):
        pass

    @staticmethod
    def create(text: str, text_color: tuple, font_metrics: dict) -> 'AttributedString':
        return AttributedString(None, text, text_color, font_metrics, False, None)

    @staticmethod
    def create_with_icon(icon: object, text: str, text_color: tuple, font_metrics: dict,
                         underline: bool, underline_color: tuple) -> 'AttributedString':
        if underline and not underline_color:
            raise ValueError("underline color cannot be null when underlining.")
        return AttributedString(icon, text, text_color, font_metrics, underline, underline_color)

    def __init__(self, icon: object = None, text: str = '', text_color: tuple = (0, 0, 0),
                 font_metrics: dict = {}, underline: bool = False,
                 underline_color: tuple = (0, 0, 0)):
        self.icon = icon
        self.text = text
        self.font_metrics = font_metrics
        self.text_color = text_color
        self.is_underlined = underline
        self.underline_color = underline_color

    @property
    def get_text(self) -> str:
        return self.text

    @property
    def get_icon(self) -> object:
        return self.icon

    def length(self) -> int:
        return len(self.get_text())

    def get_icon_width(self) -> int:
        if not self.icon:
            return 0
        return self.icon.width()

    # font metrics methods
    def string_width(self) -> int:
        if self.text_width == -1:
            self.text_width = self.get_icon_width() + self.font_metrics['width']
        return self.text_width

    def height_above(self) -> int:
        return self.font_metrics['ascent'] + self.font_metrics['leading']

    def height_below(self) -> int:
        return self.font_metrics['descent'] + AttributedString.UNDERLINE_HEIGHT

    def char_position(self, x: int) -> int:
        sub_width = 0
        for i in range(len(self.get_text())):
            sub_width += self.font_metrics['width']
            if sub_width > x:
                return i
        return len(self.get_text())

    @property
    def get_font_metrics(self):
        return self.font_metrics

    @property
    def get_color(self, char_index: int) -> tuple:
        return self.text_color

    # substring methods
    def substring(self, start: int = 0) -> 'AttributedString':
        new_string = AttributedString.derive_attributed_string(self.get_text()[start:])
        if start == 0 and not self.icon:
            new_string.icon = self.icon
        return new_string

    def substring(self, start: int, end: int) -> 'AttributedString':
        if start == 0 and end == len(self.get_text()):
            return self
        new_string = AttributedString.derive_attributed_string(self.get_text()[start:end])
        if start == 0:
            new_string.icon = self.icon
        return new_string

    # replace all methods
    def replace_all(self, targets: list, replacement: str) -> 'AttributedString':
        buffer = ''
        for c in self.get_text():
            if c in targets:
                buffer += replacement
            else:
                buffer += c
        return AttributedString.derive_attributed_string(buffer)

    # paint methods
    def paint(self, component: object, graphics: dict, x: int, y: int):
        if self.icon:
            self.icon.paint_icon(None, graphics['g'], x, -self.font_metrics['height'])
            x += self.icon.width()
        graphics['g'].set_font(self.font_metrics['font'])
        if self.is_underlined:
            graphics['g'].set_color(self.underline_color)
            descent = self.font_metrics['descent']
            graphics['g'].fill_rect(x, descent - AttributedString.UNDERLINE_HEIGHT,
                                    self.string_width(), AttributedString.UNDERLINE_HEIGHT)
        graphics['g'].set_color(self.text_color)
        GraphicsUtils.draw_string(component, graphics['g'], self.get_text(), x, 0)

    # factory methods
    @staticmethod
    def derive_attributed_string(new_text: str) -> 'AttributedString':
        new_string = AttributedString()
        new_string.text = new_text
        new_string.font_metrics = {}
        new_string.text_color = (0, 0, 0)
        new_string.is_underlined = False
        new_string.underline_color = (0, 0, 0)
        return new_string

    def __str__(self) -> str:
        return self.get_text()
```

Please note that Python does not have direct equivalents for Java's `Icon` and `FontMetrics`. I replaced them with more general types (`object` and `dict`, respectively).