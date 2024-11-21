import tkinter as tk

class AutocompletionCellRenderer:
    def __init__(self, owner):
        self.owner = owner

    def getListCellRendererComponent(self, list, value, index, selected, cell_has_focus):
        label = tk.Label()
        default_renderer_component = self.default_renderer.getListCellRendererComponent(list, value, index, selected, cell_has_focus)
        label.config(text=self.owner.get_completion_display(value))
        if not label.cget("text"):
            label.config(text="  ")
        font = self.owner.get_completion_font(value, selected, cell_has_focus)
        if font:
            label.config(font=font)

        icon = self.owner.get_completion_icon(value, selected, cell_has_focus)
        if icon:
            label.config(image=icon)

        fg_color = self.owner.get_completion_foreground(value, selected, cell_has_focus)
        if fg_color:
            label.config(foreground=fg_color)

        bg_color = self.owner.get_completion_background(value, selected, cell_has_focus)
        if bg_color:
            label.config(background=bg_color)

        return label

class DefaultRenderer:
    def getListCellRendererComponent(self, list, value, index, selected, cell_has_focus):
        # implement me!
        pass
