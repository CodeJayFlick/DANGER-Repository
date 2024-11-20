import tkinter as tk
from threading import Thread

class OkDialog:
    def __init__(self, title, message):
        self.root = tk.Tk()
        self.root.title(title)
        label = tk.Label(self.root, text=message)
        label.pack()
        button = tk.Button(self.root, text="OK", command=self.root.destroy)
        button.pack()

def show(title, message):
    root = tk.Toplevel()
    root.title(title)
    label = tk.Label(root, text=message)
    label.pack()
    button = tk.Button(root, text="OK", command=root.destroy)
    button.pack()
    root.mainloop()

def showError(title, message):
    show(title, message)

def showInfo(title, message):
    show(title, message)

OkDialog.show = staticmethod(show)
OkDialog.showError = staticmethod(showError)
OkDialog.showInfo = staticmethod(showInfo)
