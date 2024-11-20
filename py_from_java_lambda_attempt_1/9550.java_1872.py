Here is the translation of the Java code into Python:

```Python
class SimpleTextField:
    def __init__(self, text: str, font_metrics: dict, start_x: int, width: int,
                 allow_cursor_at_end: bool, hl_factory):
        self.text = text
        self.hl_factory = hl_factory
        self.num_cols = len(text)
        if allow_cursor_at_end:
            self.num_cols += 1

        self.font_metrics = font_metrics
        self.start_x = start_x
        self.width = width
        self.preferred_width = font_metrics['stringWidth'](text)
        self.allow_cursor_at_end = allow_cursor_at_end

    def is_allow_cursor_at_end(self):
        return self.allow_cursor_at_end

    @property
    def height_above(self):
        return self.font_metrics.get('maxAscent', 0) + self.font_metrics.get('leading', 0)

    @property
    def height_below(self):
        return self.font_metrics.get('maxDescent', 0)

    def get_width(self):
        return self.width

    def get_preferred_width(self):
        return self.preferred_width

    def get_height(self):
        return self.height_above + self.height_below

    @property
    def start_x(self):
        return self.start_x

    def get_num_data_rows(self):
        return 1

    def get_num_rows(self):
        return 1

    def get_num_cols(self, row: int) -> int:
        if row != 0:
            raise ValueError("Row must be zero")
        return self.num_cols

    def get_row(self, y: int) -> int:
        return 0

    def get_col(self, row: int, x: int) -> int:
        if x < self.start_x:
            x = self.start_x
        elif x >= self.start_x + self.width:
            x = self.start_x + self.width - 1
        col = find_column(self.text, x - self.start_x)
        if col >= self.num_cols:
            return self.num_cols - 1
        return col

    def get_y(self, row: int) -> int:
        return -self.height_above

    def get_x(self, row: int, col: int) -> int:
        x = 0
        for i in range(col):
            if i < self.num_cols:
                x += self.font_metrics['charWidth'](self.text[i])
            else:
                break
        return self.start_x + x

    def is_valid(self, row: int, col: int) -> bool:
        if row != 0:
            return False
        if (col < 0) or (col > self.num_cols - 1):
            return False
        return True

    def paint(self, c, g, context, clip, color_manager, cursor_loc, row_height: int):
        paint_selection(g, color_manager, 0)
        paint_highlights(g, self.hl_factory.get_highlights(self.text, -1))
        if not hasattr(c, 'setFont'):
            return
        c.setFont(self.font_metrics['font'])
        g.setColor(context.getForeground())
        GraphicsUtils.draw_string(c, g, self.text, self.start_x, 0)

    def paint_selection(self, g: object, color_manager: dict, row: int):
        selections = color_manager.get('selection_highlights', [])[row]
        for highlight in selections:
            g.setColor(highlight['color'])
            start_col = highlight['start']
            end_col = highlight['end']
            x1 = find_x(start_col)
            x2 = end_col >= len(self.text) and self.width or find_x(end_col)
            g.fillRect(self.start_x + x1, -self.height_above, x2 - x1, self.height_below)

    def paint_highlights(self, g: object, highlights):
        for highlight in highlights:
            start_col = max(highlight['start'], 0)
            end_col = min(highlight['end'], len(self.text))
            color = highlight['color']
            if end_col >= start_col:
                x1 = find_x(start_col)
                x2 = find_x(end_col + 1)
                g.setColor(color)
                g.fillRect(self.start_x + x1, -self.height_above, x2 - x1, self.height_below)

    def find_column(self, text: str, x: int) -> int:
        start_pos = 0
        col = 0
        for char in text:
            if hasattr(char, 'charWidth'):
                start_pos += self.font_metrics['charWidth'](char)
            else:
                break
            if x < start_pos:
                return col - (1 if allow_cursor_at_end and col == len(text) else 0)

    def paint_cursor(self, g: object, cursor_color: dict, cursor_loc):
        if not hasattr(cursor_loc, 'col'):
            return

        if cursor_loc.col() >= self.num_cols:
            return
        x = self.start_x + sum(self.font_metrics['charWidth'](c) for c in self.text[:cursor_loc.col()])
        g.setColor(cursor_color)
        g.fillRect(x - 1, -self.height_above, 2, self.height_below)

    def get_cursor_bounds(self, row: int, col: int):
        if row != 0:
            return None
        x = self.start_x + sum(self.font_metrics['charWidth'](c) for c in self.text[:col])
        return Rectangle(x - 1, -self.height_above, 2, self.height_below)

    def set_foreground(self, color: dict):
        if not hasattr(color, 'getColor'):
            raise ValueError("Color must be a valid Color object")
        self.foreground_color = color

    @property
    def foreground(self) -> dict:
        return self.foreground_color


class GraphicsUtils:

    @staticmethod
    def draw_string(c, g, text: str, x: int, y: int):
        if not hasattr(g, 'drawString'):
            raise ValueError("Graphics object must have a drawString method")
        font = c.getFont()
        metrics = font.get_metrics()
        ascent = metrics.getMaxAscent() + metrics.getLeading()
        descent = metrics.getMaxDescent()

        g.setFont(font)
        g.setColor(c.getForeground())
        if y < -ascent:
            y -= ascent
        elif y > descent:
            y += descent

        for char in text:
            width, height = font.charWidth(char), 0
            x1 = max(0, min(x + width, c.getWidth() - 2))
            g.drawString(text[:x], x1, y)
            if hasattr(c, 'getFontMetrics'):
                metrics = c.getFontMetrics()
                ascent = metrics.getMaxAscent() + metrics.getLeading()
                descent = metrics.getMaxDescent()

        return


class Rectangle:
    def __init__(self, x: int, y: int, width: int, height: int):
        self.x = x
        self.y = y
        self.width = width
        self.height = height

    @property
    def top(self) -> int:
        return self.y


class RowColLocation:

    def __init__(self, row: int, col: int):
        self.row = row
        self.col = col

    @property
    def row(self) -> int:
        return self.row

    @property
    def col(self) -> int:
        return self.col


# Usage example:

hl_factory = None  # Initialize the HighlightFactory object here
font_metrics = {'stringWidth': lambda s: len(s), 'charWidth': lambda c: 1, 'maxAscent': 10,
                'leading': 2, 'maxDescent': -5}
text = "Hello World"
start_x = 0
width = 100
allow_cursor_at_end = True

simple_text_field = SimpleTextField(text, font_metrics, start_x, width, allow_cursor_at_end, hl_factory)
```

This Python code is a direct translation of the provided Java code.