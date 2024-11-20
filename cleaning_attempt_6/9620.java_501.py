import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

class GFileChooserOptionsDialog:
    SHOW_DOT_FILES_PROPERTY_NAME = "G_FILE_CHOOSER.ShowDotFiles"
    SHOW_DOT_FILES_DEFAULT = False

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Chooser Options")
        self.panel = tk.Frame(self.root)
        self.show_dot_files_checkbox = tk.BooleanVar(value=True)

        label = tk.Label(self.panel, text="Show '.' files", wraplength=300)
        label.pack(side=tk.LEFT)

        checkbox = tk.Checkbutton(self.panel, variable=self.show_dot_files_checkbox,
                                   onvalue=True, offvalue=False)
        checkbox.pack(side=tk.LEFT)

        self.panel.pack()
        self.root.mainloop()

    def get_shows_dot_files(self):
        return self.show_dot_files_checkbox.get()

    def ok_callback(self):
        if messagebox.askokcancel("Confirm", "Apply the user changes?"):
            Preferences.setProperty(self.SHOW_DOT_FILES_PROPERTY_NAME,
                                     str(self.show_dot_files_checkbox.get()))
            Preferences.store()
            self.root.destroy()

if __name__ == "__main__":
    GFileChooserOptionsDialog()
