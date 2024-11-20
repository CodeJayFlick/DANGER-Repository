import tkinter as tk
from tkinter import scrolledtext, messagebox
from PIL import ImageTk, Image

class MultiLineMessageDialog:
    ERROR_MESSAGE = 0
    INFORMATION_MESSAGE = 1
    WARNING_MESSAGE = 2
    QUESTION_MESSAGE = 3
    PLAIN_MESSAGE = 4

    def __init__(self, title, short_message, detailed_message, message_type, modal):
        self.root = tk.Tk()
        self.root.title(title)
        if not short_message:
            return
        label = tk.Label(self.root, text=short_message)
        label.pack(padx=(5, 0), pady=(10, 0))
        
        if detailed_message and HTMLUtilities.is_html(detailed_message):
            text_area = scrolledtext.ScrolledText(self.root, width=60, height=15)
            text_area.insert('1.0', detailed_message[6:])
            text_area.config(state='disabled')
            self.root.geometry(f"600x300")
        else:
            text_area = tk.Text(self.root, width=60, height=15)
            text_area.insert('1.0', detailed_message)
            text_area.config(state='disabled')

        if message_type != MultiLineMessageDialog.PLAIN_MESSAGE:
            icon_path = OptionDialog.get_icon_for_message_type(message_type)
            image = Image.open(icon_path).resize((20, 20))
            label = tk.Label(self.root, image=ImageTk.PhotoImage(image), borderwidth=1)
            label.pack(side=tk.LEFT)

        self.ok_button = tk.Button(self.root, text='OK', command=self.close)
        self.ok_button.pack(padx=(5, 0))

    def close(self):
        self.root.destroy()

def showModalMessageDialog(parent, title, short_message, detailed_message, message_type):
    dialog = MultiLineMessageDialog(title, short_message, detailed_message, message_type, True)
    parent.wait_window(dialog.root)

def showMessageDialog(parent, title, short_message, detailed_message, message_type):
    dialog = MultiLineMessageDialog(title, short_message, detailed_message, message_type, False)
    parent.wait_window(dialog.root)
