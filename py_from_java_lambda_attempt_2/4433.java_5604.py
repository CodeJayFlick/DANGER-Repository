Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

class DomainEventComponentProvider:
    LIMIT = 200
    ICON = None

    def __init__(self):
        self.text_area = scrolledtext.ScrolledText()
        self.scroll-pane = tk.Frame()
        self.clear_action = None
        self.event_list = []

    def set_icon(self, icon):
        self.ICON = icon

    def get_component(self):
        return self.scroll-pane

    def component_hidden(self):
        self.clear()

    def get_font(self):
        return self.text_area.font

    def set_font(self, font):
        self.text_area.config(font=font)

    def create_action(self):
        if not self.ICON:
            from PIL import ImageTk
            icon = ImageTk.PhotoImage(file='images/monitor.png')
            self.set_icon(icon)
        
        self.clear_action = tk.Button(self.scroll-pane, text="Clear Display", command=self.clear)
        self.clear_action.pack(side=tk.LEFT)

    def clear(self):
        self.text_area.delete(1.0, 'end')
        self.event_list.clear()

    def display_event(self, event_str):
        if len(self.event_list) < self.LIMIT:
            self.text_area.insert('end', event_str)
        else:
            if len(self.event_list) > self.LIMIT:
                list = self.event_list[100:]
                self.event_list = list
            self.text_area.delete(1.0, 'end')
            for str in self.event_list:
                self.text_area.insert('end', str)

    def run(self):
        root = tk.Tk()
        root.title("Domain Object Event Display")
        
        self.scroll-pane.pack(side=tk.BOTTOM)
        self.create_action()

        root.mainloop()

if __name__ == "__main__":
    provider = DomainEventComponentProvider()
    provider.run()
```

Please note that this Python code uses the `tkinter` library for creating a GUI, which is not exactly equivalent to Java's Swing.