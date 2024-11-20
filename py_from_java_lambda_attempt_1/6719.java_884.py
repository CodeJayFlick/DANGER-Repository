Here is the translation of the Java code into Python:

```Python
class ByteField:
    def __init__(self, text: str, font_metrics: dict, start_x: int, width: int,
                 allow_cursor_at_end: bool, field_offset: int, index: int, hl_factory):
        super().__init__()
        self.field_offset = field_offset
        self.index = index
        self.cursor_width = font_metrics['charWidth']('W')

    def paint(self, c, g, context, clip, color_manager, cursor_loc, row_height):
        self.paint_selection(g, color_manager, 0)
        highlights = hl_factory.get_highlights(self, text, -1)
        if highlights:
            self.paint_highlights(g, highlights)

        font = metrics['font']
        foreground_color = None
        if not foreground_color:
            foreground_color = context.foreground

        g.set_font(font)
        g.set_color(foreground_color)
        graphics_utils.draw_string(c, g, text, start_x, 0)

        cursor_color = context.cursor_color
        self.paint_cursor(c, g, cursor_color, cursor_loc, not context.cursor_hidden())

    def paint_cursor(self, c, g, cursor_color, cursor_loc, hidden):
        if not cursor_loc:
            return

        x = start_x + metrics['stringWidth'](text[:cursor_loc.col])
        g.set_color(cursor_color)
        g.fill_rect(x, -height_above, self.cursor_width, height_above + height_below)

        if hidden:
            return  # no cursor showing; no text to repaint
        else:
            old_clip = g.get_clip()
            try:
                g.set_clip(x, -height_above, self.cursor_width, height_above + height_below)
                text_color = color_utils.contrast_foreground(cursor_color)
                g.set_color(text_color)
                graphics_utils.draw_string(c, g, text, start_x, 0)
            finally:
                g.set_clip(old_clip)

    def get_field_offset(self):
        return self.field_offset

    def get_index(self):
        return self.index

    def __str__(self):
        return str(self.get_text())
```

Please note that Python does not have direct equivalent of Java's `Graphics`, `FontMetrics` and other classes. I've replaced them with dictionary (`font_metrics`) in the above code, which is a common practice when porting Java to Python.