import tkinter as tk
from tkinter import messagebox

class Client:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Client System")
        self.filter_manager = None
        self.jl = tk.Label(self.root, text="RUNNING...")
        self.jt_fields = [tk.Entry() for _ in range(3)]
        self.jt_areas = [tk.Text() for _ in range(2)]
        self.clear_button = tk.Button(self.root, text="Clear", command=self.on_clear)
        self.process_button = tk.Button(self.root, text="Process", command=self.on_process)

        self.setup()

    def setup(self):
        self.root.geometry("300x300")
        frame = tk.Frame(self.root)
        frame.pack()
        self.jl.pack(side=tk.BOTTOM)
        for i in range(3):
            label = tk.Label(frame, text=f"Field {i+1}")
            label.grid(row=i, column=0)
            self.jt_fields[i].grid(row=i, column=1)

        for i in range(2):
            label = tk.Label(frame, text="Area")
            label.grid(row=i+3, column=0)
            self.jt_areas[i].grid(row=i+3, column=1)

        clear_button_frame = tk.Frame(self.root)
        clear_button_frame.pack()
        self.clear_button.pack(side=tk.LEFT)
        process_button_frame = tk.Frame(self.root)
        process_button_frame.pack()
        self.process_button.pack()

    def on_clear(self):
        for area in self.jt_areas:
            area.delete(1.0, "end")
        for field in self.jt_fields:
            field.delete(0, "end")

    def on_process(self):
        order = Order(
            self.jt_fields[0].get(),
            self.jt_fields[1].get(),
            self.jt_areas[0].get("1.0", "end"),
            self.jt_fields[2].get(),
            self.jt_areas[1].get("1.0", "end")
        )
        result = self.filter_manager.filter_request(order)
        self.jl.config(text=result)

    def run(self):
        self.root.mainloop()

class Order:
    def __init__(self, name, contact_number, address, deposit_number, order):
        self.name = name
        self.contact_number = contact_number
        self.address = address
        self.deposit_number = deposit_number
        self.order = order

if __name__ == "__main__":
    client = Client()
    client.run()

