Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk

class GTreeRenderer:
    VALID_DROP_TARGET_COLOR = '#C0C0FF'
    DEFAULT_MIN_ICON_WIDTH = 22

    def __init__(self):
        self.drop_target = None
        self.paint_drop_target = False
        self.cached_default_font = None
        self.cached_bold_font = None
        self.min_icon_width = self.DEFAULT_MIN_ICON_WIDTH

    def get_tree_cell_renderer_component(self, tree, value, selected1, expanded, leaf, row, has_focus):
        super().get_tree_cell_renderer_component(tree, value, selected1, expanded, leaf, row, has_focus)

        # Important - make sure this happens before the setBackground() call
        self.paint_drop_target = (value == self.drop_target)

        self.set_opaque(True)
        if selected1:
            self.configure(background=self.get_background_selection_color())
        else:
            self.configure(background=self.get_background_non_selection_color())

        if not isinstance(value, GTreeNode):
            return

        node = value
        text = node.display_text()
        self.config(text=text)
        self.tooltiptext(node.tool_tip())

        icon = node.icon(expanded)
        if icon is None:
            icon = self.icon()
        else:
            self.configure(icon=icon)

        update_icon_text_gap(self, icon, self.min_icon_width)

    def set_background_selection_color(self, new_color):
        super().set_background_selection_color(new_color)

    def set_background_non_selection_color(self, new_color):
        super().set_background_non_selection_color(new_color)

    def from_ui_resource(self, c):
        if isinstance(c, ColorUIResource):
            return '#%06x' % c.get_rgb()
        else:
            return str(c)

    def update_icon_text_gap(self, icon, min_width):
        self.configure(icontextgap=max(min_width - icon.width(), 2))

    @property
    def min_icon_width(self):
        return self._min_icon_width

    @min_icon_width.setter
    def min_icon_width(self, value):
        self._min_icon_width = value

    def get_font(self, bold=False):
        font = self.cget('font')
        if font != self.cached_default_font and font != self.cached_bold_font:
            self.cached_default_font = font
            self.cached_bold_font = tk.Font(family=font.split()[0], weight='bold', size=int(font[1:]))
        return bold and self.cached_bold_font or self.cached_default_font

    def set_renderer_drop_target(self, target):
        self.drop_target = target


class GTreeNode:
    pass  # This class is not implemented in the provided Java code.