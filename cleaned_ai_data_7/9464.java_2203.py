import tkinter as tk
from PIL import Image, ImageDraw, Font

class NumberIcon:
    def __init__(self, number):
        self.number = str(number)

    def set_number(self, number):
        self.number = str(number)
        self.best_font_size = -1

    def paint_icon(self, canvas: tk.Canvas, x: int, y: int) -> None:
        canvas.create_rectangle(x, y, x + 16, y + 16, fill='white')
        canvas.create_rectangle(x, y, x + 16, y + 16, outline='#b5d5ff')

        font_size = self.get_max_font_size(canvas, 15, 15)
        original_font = canvas.font
        text_font = Font(family="Arial", size=int(font_size), bold=True)

        if not hasattr(self, 'text_font'):
            self.text_font = text_font

        canvas.itemconfig('font', font=text_font)

        string_bounds = canvas.bbox(self.number)
        text_height = abs(string_bounds[3] - string_bounds[1])
        icon_height = 16
        space = y + icon_height - text_height
        half_space = int(space / 2)
        baseline_y = y + icon_height - half_space

        text_width = abs(string_bounds[2] - string_bounds[0])
        icon_width = 16
        half_width = int(icon_width / 2)
        half_text_width = int(text_width / 2)
        baseline_x = x + (half_width - half_text_width)

        canvas.create_text(baseline_x, baseline_y, text=self.number, font=text_font, fill='black')

    def get_max_font_size(self, canvas: tk.Canvas, width: int, height: int) -> float:
        if self.best_font_size > 0:
            return self.best_font_size

        size = 12
        while True:
            try:
                text_width = abs(canvas.bbox(str(size))[2] - canvas.bbox(str(size))[0])
                if text_width <= width and height >= int(abs(canvas.font.metrics().linesize)):
                    break
            except tk.TclError:
                return self.best_font_size

            size -= 1

        self.best_font_size = size
        return size

    def get_icon_height(self) -> int:
        return 16

    def get_icon_width(self) -> int:
        return 16


# Example usage:

root = tk.Tk()
canvas = tk.Canvas(root, width=200, height=100)
icon = NumberIcon(12345)

icon.paint_icon(canvas, 0, 0)

root.mainloop()
