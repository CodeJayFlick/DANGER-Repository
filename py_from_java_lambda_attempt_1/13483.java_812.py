Here is your Java code translated into Python:

```Python
import tkinter as tk
from PIL import Image, ImageDraw


class TextFormatter:
    def __init__(self, line_count=0, width=0, top_margin=0, left_margin=0, line_padding=0):
        self.line_height = 20
        self.font_size = 14
        self.image_width = width
        self.image_height = line_count * (line_height + line_padding) + top_margin * 2
        self.top_margin = top_margin
        self.left_margin = left_margin
        self.line_padding = line_padding
        self.x = left_margin
        self.y = top_margin

    def create_empty_image(self):
        image = Image.new('RGB', (self.image_width, self.image_height), 'white')
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, self.image_width - 1, self.image_height - 1), fill='black')

    def initialize_sizes(self, font_size=14):
        if not hasattr(self, 'font'):
            self.font = tk.Font(family="Monospaced", size=self.font_size)
        self.line_height += 2 * self.line_padding
        self.baseline_offset = self.font.ascent() + self.line_padding

    def write(self, text, context=None):
        if not hasattr(self, 'image'):
            self.create_empty_image()
        draw = ImageDraw.Draw(self.image)

        for match in re.finditer(r'\|(.+?)\|', text):
            start = match.start()
            end = match.end()

            print(text[:start], context)
            print(text[start + 1:end - 1], context)
            last = end

    def writeln(self, text, context=None):
        self.write(text, context)
        new_line()

    def out(self, text, fg_color='black', bg_color='white', cursor_color='red'):
        draw = ImageDraw.Draw(self.image)

        if bg_color:
            draw.rectangle((self.x, self.y + self.line_padding,
                            min(self.x + len(text) * 10, self.image_width - 1),
                            self.y + self.line_height), fill=bg_color)
        else:
            draw.rectangle((0, 0, self.image_width - 1, self.image_height - 1), fill='white')

        if fg_color:
            draw.text((self.x, self.y + self.baseline_offset), text,
                      font=self.font, fill=fg_color)

        if cursor_color:
            draw.line([(self.x, self.y + self.line_padding),
                       (self.x, self.y + self.baseline_offset)], fill=cursor_color)
        else:
            pass

    def color_lines(self, c, line_number, n_lines):
        draw = ImageDraw.Draw(self.image)

        if not hasattr(self, 'image'):
            return
        y_pos = self.top_margin + (line_number - 1) * self.line_height
        height = n_lines * self.line_height

        draw.rectangle((0, y_pos, self.image_width - 1, y_pos + height), fill=c)

    def new_line(self):
        if not hasattr(self, 'image'):
            return
        self.x = self.left_margin
        self.y += self.line_height
        return self


class TextFormatterContext:
    def __init__(self, fg_color='black', bg_color='white', cursor_color=None):
        self.fg_color = fg_color
        self.bg_color = bg_color
        self.cursor_color = cursor_color

    def get_fg(self):
        return self.fg_color

    def get_bg(self):
        return self.bg_color

    def get_cursor(self):
        return self.cursor_color


def new_line():
    pass
```

This Python code does not include the `java.awt` and `java.util.regex` packages, as they are specific to Java. Instead, it uses the PIL (Python Imaging Library) for image manipulation and tkinter for font rendering.

Please note that this is a direct translation of your Java code into Python, without any modifications or optimizations.