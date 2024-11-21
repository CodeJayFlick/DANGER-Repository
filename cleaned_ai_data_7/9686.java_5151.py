import tkinter as tk
from PIL import ImageTk, Image

class MultiLineLabel(tk.Frame):
    def __init__(self, parent=None, label="", margin_width=10, margin_height=10, alignment=tk.CENTER):
        super().__init__(parent)
        self.parent = parent
        self.label = label
        self.margin_width = margin_width
        self.margin_height = margin_height
        self.alignment = alignment

    def new_label(self, text):
        if not text:
            return "No label given for this dialog.\nThis was likely due to an exception with no message from the line of code below:\n\n" + get_caller_string()
        lines = text.split("\n")
        num_lines = len(lines)
        self.lines = lines
        self.num_lines = num_lines

    def measure(self):
        font_metrics = self.parent.cget("font").metrics()
        self.line_height = font_metrics.height
        self.max_width = 0
        for i in range(num_lines):
            line_widths[i] = font_metrics.width(lines[i])
            if line_widths[i] > max_width:
                max_width = line_widths[i]

    def set_label(self, text):
        new_label(text)
        measure()
        self.parent.update()

    def get_label(self):
        return "\n".join(self.lines)

    def set_font(self, font):
        super().set_font(font)
        measure()
        self.parent.update()

    def set_foreground(self, color):
        super().set_foreground(color)
        self.parent.update()

    def set_alignment(self, alignment):
        self.alignment = alignment
        self.parent.update()

    def set_margin_width(self, margin_width):
        self.margin_width = margin_width
        self.parent.update()

    def set_margin_height(self, margin_height):
        self.margin_height = margin_height
        self.parent.update()

    def get_alignment(self):
        return self.alignment

    def get_margin_width(self):
        return self.margin_width

    def get_margin_height(self):
        return self.margin_height

    def add_notify(self):
        super().add_notify()
        measure()
        self.parent.update()

    def get_preferred_size(self):
        return (max_width + 2 * margin_width, num_lines * line_height + 2 * margin_height)

    def paint(self, canvas):
        x = y = 0
        for i in range(num_lines):
            if alignment == tk.LEFT:
                x = margin_width
            elif alignment == tk.CENTER:
                x = (canvas.winfo_reqwidth() - line_widths[i]) // 2
            else:  # RIGHT
                x = canvas.winfo_reqwidth() - margin_width - line_widths[i]
            y += line_height
            canvas.create_text(x, y, text=lines[i], font=self.parent.cget("font"))

def get_caller_string():
    return "No caller string available"

root = tk.Tk()
mlab = MultiLineLabel(root, label="This is a test\nof a multi-line label\nLine One\n\nLine Two\nLine Three.", margin_width=20, margin_height=20, alignment=tk.CENTER)
frame = tk.Frame(root)
frame.pack(fill='both', expand=True)
mlab.pack(fill='both', expand=True)

root.mainloop()
