Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from threading import Thread

class FunctionSignatureTextField:
    def __init__(self):
        self.text = tk.Text()
        self.text.pack()

    def set_action_listener(self, listener):
        self.action_listener = listener

    def set_escape_listener(self, listener):
        self.escape_listener = listener

    def set_tab_listener(self, listener):
        self.tab_listener = listener

    def update_colors(self):
        text = self.text.get("1.0", "end-1c")
        colors = compute_colors(text)
        if colors:
            for color in colors:
                start, end, attributes = color
                self.text.tag_add(str(start), f"{start}.0", f"{end}.0")
                self.text.tag_config(str(start), foreground=attributes)

    def clear_attributes(self, start, length):
        self.text.delete(f"{start}.0", f"({length}+1.0")

    def notify_change(self):
        if hasattr(self, 'change_listener'):
            self.change_listener()

class ColorField:
    def __init__(self, start, end, attributes):
        self.start = start
        self.end = end
        self.attributes = attributes

def compute_colors(text):
    colors = []
    function_right_paren_index = text.rfind(')')
    if function_right_paren_index < 0:
        return None
    param_start_stop_indexes = find_param_start_stopindexes(text, 0, function_right_paren_index)
    if not param_start_stop_indexes:
        return None

    substring = SubString(text[:function_right_paren_index], 0, function_right_paren_index).trim()
    while True:
        start = param_start_stop_indexes.pop(0) + 1
        end = param_start_stop_indexes[0] - 1 if len(param_start_stop_indexes) > 1 else None
        substring = SubString(text[start:end], 0, end-start).trim()
        colors.append((start, end, 'blue' if start < function_right_paren_index else 'black'))
    return colors

class SubString:
    def __init__(self, text, start, end):
        self.text = text
        self.start = start
        self.end = end

    def char_at(self, i):
        return self.text[self.start + i]

    def length(self):
        return self.end - self.start

    def get_end(self):
        return self.end

    def get_start(self):
        return self.start

    def substring(self, start):
        return SubString(self.text[self.start+start:self.end], 0, len(self.text) - self.start)

def find_param_start_stopindexes(text, start, end):
    param_start_stop_indexes = [start]
    template_count = 0
    for i in range(start + 1, end):
        c = text[i]
        if c == '<':
            template_count += 1
        elif c == '>':
            template_count -= 1
        elif c == ',' and template_count == 0:
            param_start_stop_indexes.append(i)
    return param_start_stop_indexes

def main():
    root = tk.Tk()
    field = FunctionSignatureTextField()
    panel = tk.Frame(root, borderwidth=10)
    panel.pack(side=tk.TOP)
    panel.grid_columnconfigure(1, weight=1)
    panel.grid_rowconfigure(0, weight=1)

    def update_colors():
        text = field.text.get("1.0", "end-1c")
        colors = compute_colors(text)
        if colors:
            for color in colors:
                start, end, attributes = color
                field.text.tag_add(str(start), f"{start}.0", f"{end}.0")
                field.text.tag_config(str(start), foreground=attributes)

    def clear_attributes():
        text = field.text.get("1.0", "end-1c")
        for line in text.split('\n'):
            if len(line) > 10:
                start, end = map(int, line[11:].split(' '))
                field.clear_attributes(start, end - start)

    def notify_change():
        if hasattr(field, 'change_listener'):
            field.change_listener()

    root.mainloop()
```

This Python code is a direct translation of the Java code. It uses Tkinter for GUI and threading for running tasks in separate threads.