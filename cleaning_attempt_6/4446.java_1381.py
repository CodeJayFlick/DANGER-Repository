import threading
from tkinter import Tk, Label, Frame, Button, StringVar
import psutil

class ShowMemoryDialog:
    def __init__(self):
        self.root = Tk()
        self.root.title("VM Memory Usage")
        self.max_mem_label = Label(self.root)
        self.total_mem_label = Label(self.root)
        self.free_mem_label = Label(self.root)
        self.used_mem_label = Label(self.root)

        frame = Frame(self.root, borderwidth=10, relief='ridge')
        frame.pack()

        max_memory_label = Label(frame, text="Max Memory:")
        total_memory_label = Label(frame, text="Total Memory:")
        free_memory_label = Label(frame, text="Free Memory:")
        used_memory_label = Label(frame, text="Used Memory:")

        self.max_mem_label.grid(row=0, column=1)
        max_memory_label.grid(row=0, column=0)
        total_memory_label.grid(row=1, column=0)
        self.total_mem_label.grid(row=1, column=1)
        free_memory_label.grid(row=2, column=0)
        self.free_mem_label.grid(row=2, column=1)
        used_memory_label.grid(row=3, column=0)
        self.used_mem_label.grid(row=3, column=1)

    def update_labels(self):
        memory_info = psutil.virtual_memory()
        max_memory = memory_info.total / 1024
        total_memory = memory_info.total / 1024
        free_memory = memory_info.free / 1024
        used_memory = (memory_info.total - memory_info.free) / 1024

        self.max_mem_label.config(text=f"{max_memory:.0f}K")
        self.total_mem_label.config(text=f"{total_memory:.0f}K")
        self.free_mem_label.config(text=f"{free_memory:.0f}K")
        self.used_mem_label.config(text=f"{used_memory:.0f}K")

    def start_timer(self):
        threading.Thread(target=self.update_labels).start()

    def cancel_callback(self):
        self.root.destroy()
        print("Dialog canceled.")

    def ok_callback(self):
        psutil.gc.collect()
