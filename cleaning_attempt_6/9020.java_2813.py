import tkinter as tk
from typing import List

class VTMarkupStatusIcon:
    BORDER = 2
    WIDTH = 44
    KNOB_WIDTH = 4
    HEIGHT = 16

    def __init__(self):
        self.status = VTAssociationMarkupStatus(0xff)

    def get_icon_height(self) -> int:
        return self.HEIGHT

    def get_icon_width(self) -> int:
        return self.WIDTH + self.KNOB_WIDTH

    def set_status(self, status: 'VTAssociationMarkupStatus') -> None:
        self.status = status

    def paint_icon(self, c: tk.Canvas, g: tk.Graphics, x: int, y: int) -> None:
        colors = self.get_colors(self.status)
        num_colors = len(colors)

        size = 0
        if num_colors > 0:
            size = (self.WIDTH - 2 * self.BORDER - 1) / num_colors

        if self.status.has_unexamined_markup():
            size /= 2

        for i in range(num_colors):
            start_x = int(i * size)
            end_x = int((i + 1) * size)
            width = end_x - start_x
            self.draw_bar(g, x + start_x + self.BORDER + 1, y + self.BORDER + 1, width, colors[i])

        g.set_color('black')
        g.rectangle(x, y, self.WIDTH, self.HEIGHT)

    def draw_bar(self, g: tk.Graphics, x: int, y: int, width: int, color: str) -> None:
        g.set_color(color)
        g.fill_rectangle(x, y, width, self.HEIGHT - 2 * self.BORDER - 1)

    def get_colors(self, status: 'VTAssociationMarkupStatus') -> List[str]:
        colors = []
        if status.has_rejected_markup():
            colors.append('red')
        if status.has_applied_markup() or status.is_fully_applied():
            colors.append('green')
        if status.has_dont_care_markup():
            colors.append('blue')
        if status.has_dont_know_markup():
            colors.append('orange')

        return colors

class VTAssociationMarkupStatus:
    def __init__(self, value: int):
        self.value = value
