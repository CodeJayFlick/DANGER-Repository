Here is the translation of the Java code into Python:

```Python
from tkinter import *
import os

class ColumnFilterArchiveDialog:
    def __init__(self, filter_dialog, manager, table_name):
        self.filter_dialog = filter_dialog
        self.manager = manager
        self.table_name = table_name
        
        root = Tk()
        root.title("Saved Table Column Filters")
        
        if not os.path.isblank(table_name):
            sb = "Saved Table Column Filters for '{}'"
            root.title(sb.format(table_name))
            
        panel = Panel(root)
        panel.pack(fill=BOTH, expand=1)

    def get_selected_column_filter(self):
        return self.selected_column_filter

    def ok_callback(self):
        close()
        
    def cancel_callback(self):
        if hasattr(self, 'selected_column_filter'):
            del self.selected_column_filter
        super().cancel_callback()

class Panel:
    def __init__(self, master):
        frame = Frame(master)
        frame.pack(fill=BOTH, expand=1)

class GDHtmlLabel:
    pass

def close():
    root.destroy()
    
root.mainloop()
```

Please note that this is a direct translation of the Java code into Python. The original code was written for Java Swing and does not directly translate to pure Python (which uses tkinter).