Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class MergeProgressPanel:
    DEFINED_ICON = None
    IN_PROGRESS_ICON = None
    COMPLETED_ICON = None

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Merge Progress Panel")
        self.frame = tk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

    def add_info(self, phase):
        label_panel = tk.LabelFrame(self.frame, text=phase[-1], borderwidth=0)
        image_label = tk.Label(label_panel, image=self.DEFINED_ICON)
        image_label.image = self.DEFINED_ICON
        label_panel.pack(fill="x", padx=20)

    def set_in_progress(self, phase):
        icon_label = self.frame.winfo_children()[self.frame.winfo_children().index(phase[-1]) - 1]
        if isinstance(icon_label, tk.Label):
            icon_label.config(image=self.IN_PROGRESS_ICON)
            icon_label.image = self.IN_PROGRESS_ICON

    def set_completed(self, phase):
        icon_label = self.frame.winfo_children()[self.frame.winfo_children().index(phase[-1]) - 1]
        if isinstance(icon_label, tk.Label):
            icon_label.config(image=self.COMPLETED_ICON)
            icon_label.image = self.COMPLETED_ICON


def main():
    panel = MergeProgressPanel()

    MEMORY = ["Memory"]
    PROGRAM_TREE = ["Program Tree"]
    DATA_TYPES = ["Data Types"]
    PROGRAM_CONTEXT = ["Program Context"]
    LISTING = ["Listing"]
    BYTES = ["Listing", "Bytes"]
    CODE_UNITS = ["Listing", "Code Units"]
    FUNCTIONS = ["Listing", "Functions"]
    SYMBOLS = ["Listing", "Symbols"]
    COMMENTS = ["Listing", "Comments, References & User Defined Properties"]
    EXTERNAL_PROGRAM = ["External Program"]
    PROPERTY_LIST = ["Property List"]

    panel.add_info(MEMORY)
    panel.add_info(PROGRAM_TREE)
    panel.add_info(DATA_TYPES)
    panel.add_info(PROGRAM_CONTEXT)
    panel.add_info(LISTING)
    panel.add_info(BYTES)
    panel.add_info(CODE_UNITS)
    panel.add_info(FUNCTIONS)
    panel.add_info(SYMBOLS)
    panel.add_info(COMMENTS)
    panel.add_info(EXTERNAL_PROGRAM)
    panel.add_info(PROPERTY_LIST)

    try:
        # Set the icons
        for i, phase in enumerate([MEMORY, PROGRAM_TREE, DATA_TYPES]):
            if i == 0:
                panel.set_in_progress(phase)
                tk.mainloop()
                time.sleep(2)
                panel.set_completed(phase)
            elif i < len(MEMORY) - 1:
                panel.set_in_progress(phase)
                tk.mainloop()
                time.sleep(2)
                panel.set_completed(phase)

    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

```

Please note that Python does not have direct equivalent of Java's Swing library. However, we can use Tkinter for creating GUI in Python.

Also, please ensure you have the necessary modules installed (PIL) and import them correctly before running this code.