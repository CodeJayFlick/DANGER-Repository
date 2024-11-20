import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog

class ReadTextDialog:
    def __init__(self, title, text):
        self.root = tk.Tk()
        self.root.title(title)
        self.text_area = scrolledtext.ScrolledText(self.root, width=80, height=10)
        self.text_area.insert('1.0', text)
        self.text_area.configure(state='disabled')
        self.text_area.pack(fill=tk.BOTH, expand=True)

    def get_text(self):
        return self.text_area.get('1.0', 'end-1c')

    def set_text(self, text):
        self.text_area.delete('1.0', 'end-1c')
        self.text_area.insert('1.0', text)
        self.text_area.configure(state='disabled')

    def show_dialog(self):
        self.root.mainloop()

# Example usage:
dialog = ReadTextDialog("Read Text", "This is some sample text.")
dialog.show_dialog()
