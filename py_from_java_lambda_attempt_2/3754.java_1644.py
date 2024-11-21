Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox

class ConflictDialog:
    REPLACE = 1
    USE_EXISTING = 2
    RENAME = 3

    def __init__(self, dt_name, category_path, new_dt_name):
        self.apply_to_all = False
        self.selected_option = self.RENAME

        root = tk.Tk()
        root.title("Data Type Conflict for " + dt_name)

        main_panel = tk.Frame(root)
        main_panel.pack(fill="both", expand=True)

        top_label = tk.Label(main_panel, text="Resolve Data Type Conflict")
        top_label.pack(pady=(10, 0))

        button_frame = tk.Frame(main_panel)
        button_frame.pack()

        rename_button = tk.Radiobutton(button_frame, text="Rename new data type to " + new_dt_name, variable=tk.IntVar(), value=self.RENAME)
        replace_button = tk.Radiobutton(button_frame, text="Replace existing data type", variable=tk.IntVar(), value=self.USE_EXISTING)
        use_existing_button = tk.Radiobutton(button_frame, text="Use existing data type", variable=tk.IntVar(), value=self.REPLACE)

        rename_button.pack(side=tk.LEFT)
        replace_button.pack(side=tk.LEFT)
        use_existing_button.pack(side=tk.LEFT)

        def apply_to_all_callback():
            self.apply_to_all = True
            root.destroy()

        apply_to_all_button = tk.Button(button_frame, text="Apply to All", command=apply_to_all_callback)
        apply_to_all_button.pack(side=tk.RIGHT)

        def ok_callback():
            root.destroy()

        def cancel_callback():
            root.destroy()

        top_label = tk.Label(main_panel, text=f"Conflict exists in {category_path} for {dt_name}")
        top_label.pack(pady=(10, 0))

        root.mainloop()
```

This Python code creates a simple GUI dialog with radio buttons and an "Apply to All" button. The `okCallback` method is not implemented as it's not clear what the OK button should do in this context.