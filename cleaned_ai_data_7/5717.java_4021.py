import tkinter as tk

class FixedLengthTextField(tk.Text):
    def __init__(self, text="", size_component=None):
        super().__init__()
        self.insert("1.0", text)
        if size_component:
            self.size_component = size_component
        else:
            self.size_component = None

    def get_preferred_size(self):
        insets = self.size_component.insets()
        textSize = tk.Dimension(
            width=self.size_component.width - insets.left,
            height=super().get_preferred_size().height)
        super().set_preferred_size(textSize)
        return textSize
