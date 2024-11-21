import tkinter as tk
from tkinter import simpledialog

class NumberRangeInputDialog:
    def __init__(self, title, label):
        self.was_cancelled = False
        self.input_label = label
        self.initial_value = ""
        self.range_list = []
        self.text_field = None
        self.key_listener = None

        root = tk.Tk()
        root.title(title)

        key_listener = self.KeyAdapter()

        self.text_field = tk.Text(root, width=20)
        self.text_field.insert('1.0', label + '\n')
        self.text_field.bind('<Key>', key_listener.on_key_press)
        self.text_field.pack(fill='x')

    def show(self):
        root.mainloop()
        return not self.was_cancelled

    class KeyAdapter:
        def on_key_press(self, event):
            if event.keysym == 'Return':
                self.ok_callback()

        def ok_callback(self):
            self.was_cancelled = False
            try:
                ranges = [int(x) for x in self.text_field.get('1.0', 'end-1c').split(',')]
                range_list = []
                for r in ranges:
                    if ',' not in str(r):
                        range_list.append((r, r))
                    else:
                        start, end = map(int, str(r).split(':'))
                        range_list.extend([(x, x) for x in range(start, end+1)])
            except ValueError as e:
                self.was_cancelled = True
                return

    def get_text_field(self):
        return self.text_field


# Example usage:

dialog = NumberRangeInputDialog("Number Range Input Dialog", "Enter number ranges (e.g. 2,5 or 1:4):")
if dialog.show():
    print(dialog.get_text_field().get('1.0', 'end-1c'))
else:
    print("Cancelled")

