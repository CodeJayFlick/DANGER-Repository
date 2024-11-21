Here is the translation of the given Java code into Python:

```Python
import os
from tkinter import *
from tkinter.filedialog import *

class FileChooserEditor:
    def __init__(self):
        self.current_file_value = None
        self.text_field = Entry(width=20)
        self.browse_button = Button(text="Browse", command=self.display_file_chooser)

    def get_as_text(self):
        return self.text_field.get().strip()

    def get_value(self):
        text = self.get_as_text()
        if not text:
            return None
        return os.path.abspath(os.path.expanduser(text))

    def set_as_text(self, text):
        if not text or not text.strip():
            self.current_file_value = None
            self.text_field.delete(0, END)
            return

        self.current_file_value = os.path.normpath(os.path.join(os.getcwd(), text))
        self.text_field.insert(END, text)

    def set_value(self, value):
        if value is None:
            self.current_file_value = None
        elif isinstance(value, str):
            self.set_as_text(value)
        else:
            file_path = str(value)
            if os.path.exists(file_path):
                directory = os.path.dirname(file_path)
                if os.path.isdir(directory):
                    self.text_field.insert(END, file_path)

    def supports_custom_editor(self):
        return True

    def get_custom_editor(self):
        panel = FileChooserPanel()
        panel.textField = self.text_field
        panel.browse_button.config(command=self.display_file_chooser)
        return panel

class FileChooserPanel:
    def __init__(self):
        self.panel = Tk()

        self.textField = Entry(width=20, text="")
        self.browse_button = Button(text="Browse", command=lambda: self.display_file_chooser())

        self.panel.title("FileChooserEditor")
        self.panel.geometry('300x100')

        self.text_field.pack()
        self.browse_button.pack(pady=(5, 0))

    def display_file_chooser(self):
        file_path = self.textField.get().strip()

        if os.path.exists(file_path):
            directory = os.path.dirname(file_path)
            if os.path.isdir(directory):
                current_directory = directory
            else:
                parent_dir = os.path.dirname(os.getcwd())
                while not os.path.exists(parent_dir) and parent_dir != '/':
                    parent_dir = os.path.dirname(parent_dir)

        file_chooser = fd.askopenfilename(initialdir=current_directory, title="FileChooserEditor", filetypes=[("Files and Directories", "*.*)"])

        if file_path:
            self.textField.delete(0, END)
            self.textField.insert(END, file_chooser)

class Application:
    def __init__(self):
        pass

if __name__ == "__main__":
    app = Application()
```

This Python code does not include the `GhidraFileChooser` class as it is specific to Java and there isn't a direct equivalent in Python.