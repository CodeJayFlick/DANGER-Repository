Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import scrolledtext, messagebox

class MultiLineInputDialog:
    def __init__(self, title: str, message_text: str, initial_value: str = None, icon=None):
        self.is_canceled = False
        self.input_area = scrolledtext.ScrolledText()

        root = tk.Tk()
        root.title(title)

        data_panel = tk.Frame(root)
        data_panel.pack(fill=tk.BOTH, expand=True)

        message_label = tk.Label(data_panel, text=message_text)
        message_label.pack(side=tk.TOP, fill=tk.X)

        self.input_area.insert('1.0', initial_value or '')
        self.input_area.config(wrap=tk.WORD)
        self.input_area.focus_set()

        hint_label = tk.Label(data_panel, text="Control-Enter to accept", fg='light gray')
        hint_label.pack(side=tk.BOTTOM, fill=tk.X)

        icon_label = tk.Frame(root) if icon else None
        separator_line = tk.Frame(root, height=1)
        separator_line.pack(fill=tk.X)

        work_panel = tk.Frame(root)
        work_panel.pack(fill=tk.BOTH, expand=True)

        if icon:
            icon_label.pack(side=tk.LEFT, fill=tk.Y)
            work_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        else:
            data_panel.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def ok_callback(self):
        self.is_canceled = False
        root.destroy()

    def cancel_callback(self):
        self.is_canceled = True
        root.destroy()

    @property
    def is_canceled(self) -> bool:
        return self._is_canceled

    @is_canceled.setter
    def is_canceled(self, value: bool):
        self._is_canceled = value

    @property
    def value(self) -> str | None:
        if not self.is_canceled:
            return self.input_area.get('1.0', 'end-1c')
        else:
            return None


# Example usage:

root = tk.Tk()
dialog = MultiLineInputDialog("Test", "Enter Text")
root.mainloop()

```

This Python code is equivalent to the Java code provided, with some minor differences due to language-specific variations in syntax and functionality.