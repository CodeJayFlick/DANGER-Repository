Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread

class EditWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.text_field = scrolledtext.ScrolledText(self.root, width=50)
        self.active = False
        self.component = None
        self.rectangle = None
        self.listener = None

    def get_associated_component(self):
        return self.component

    def is_active(self):
        return self.active

    def set_visible(self, state):
        if not state:
            if self.component is not None:
                self.component.removecomponentlistener(self)
                if isinstance(self.component, tk.Notebook):
                    self.component.notebook().removechanger(self)
                self.root.removecomponentlistener(self)
                self.component = None
                self.listener = None

    def close(self):
        self.set_visible(False)
        self.dispose()

    def show(self, default_text, component, rectangle, edit_listener):
        if self.component is not None:
            self.set_visible(False)

        if component is None or not component.winfo_ismapped():
            return

        self.component = component
        self.rectangle = rectangle
        self.listener = edit_listener

        self.component.addcomponentlistener(self)
        if isinstance(component, tk.Notebook):
            component.notebook().addchanger(self)
        self.root.addcomponentlistener(self)

        self.set_location()

        text_field.insert('1.0', default_text or '')
        text_field.config(state='normal')
        text_field.focus_set()
        text_field.selection_range(0, len(text_field.get('1.0','end-1c')))

    def set_location(self):
        x = self.component.winfo_x() + self.rectangle.x
        y = self.component.winfo_y() + self.rectangle.y
        self.root.geometry(f'+{x+3}+{y}')

    def create(self):
        text_field.insert('1.0', '  ')
        panel = tk.Frame(self.root, bg='white')
        panel.pack(fill=tk.BOTH)

        text_field.bind('<KeyRelease>', lambda e: self.close() if e.keysym == 'Escape' else None)
        text_field.bind('<FocusOut>', lambda e: self.close())
        text_field.config(state='normal')

    def dispose(self):
        pass

class AssociatedComponentListener:
    def component_hidden(self, event):
        edit_window = EditWindow()
        edit_window.close()

    def component_resized(self, event):
        edit_window = EditWindow()
        edit_window.close()

    def component_shown(self, event):
        pass

    def component_moved(self, event):
        if self.component is not None and self.component.winfo_ismapped():
            edit_window.set_location()

    def state_changed(self, event):
        edit_window = EditWindow()
        edit_window.close()

class DockingWindowManager:
    def __init__(self):
        pass

# Usage
edit_window_manager = DockingWindowManager()
edit_window = EditWindow(edit_window_manager)
```

Please note that this translation is not a direct conversion from Java to Python. The code has been adapted and modified for the differences between the two languages, such as different event handling mechanisms (Java's AWT vs. Python's tkinter).