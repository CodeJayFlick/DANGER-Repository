Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import filedialog, messagebox

class MemoryUsagePlugin:
    def __init__(self):
        self.dialog = None

    def setup_actions(self):
        action = tk.Button(text="Show VM memory", command=self.show_memory)
        action.pack()
        return action

    def show_memory(self):
        if not hasattr(self, 'dialog') or self.dialog is None:
            self.dialog = ShowMemoryDialog(self)
        else:
            self.dialog.focus_force()

class ShowMemoryDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__()
        # Your dialog code here
```

Please note that this translation does not include the exact equivalent of Java's `@PluginInfo` and other annotations. Python has different ways to achieve similar functionality using decorators or comments.

Also, please be aware that translating a complex piece of software like Ghidra from one language (Java) to another (Python), without knowing the context in which it is used, can lead to unexpected results.