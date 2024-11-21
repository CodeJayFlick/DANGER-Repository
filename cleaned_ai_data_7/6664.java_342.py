import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog

class SequenceMiningParamsInputDialog:
    def __init__(self, title):
        self.root = tk.Tk()
        self.root.title(title)
        
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        percentage_label = tk.Label(main_frame, text="Minimum Support Percentage")
        percentage_label.pack()

        try:
            default_percentage = float(Preferences.getProperty("SequenceMiningParamsCreator_percentage"))
        except (KeyError, ValueError):
            default_percentage = 10.0

        self.percentage_entry = tk.Entry(main_frame)
        self.percentage_entry.insert(0, str(default_percentage))
        self.percentage_entry.pack()

        min_fixed_bits_label = tk.Label(main_frame, text="Minimum Number of Fixed Bits")
        min_fixed_bits_label.pack()

        try:
            default_min_fix_bits = int(Preferences.getProperty("SequenceMiningParamsCreator_minbits"))
        except (KeyError, ValueError):
            default_min_fix_bits = 16

        self.min_fixed_bits_entry = tk.Entry(main_frame)
        self.min_fixed_bits_entry.insert(0, str(default_min_fix_bits))
        self.min_fixed_bits_entry.pack()

        binary_label = tk.Label(main_frame, text="Binary Sequences")
        binary_label.pack()
        
        nibble_label = tk.Label(main_frame, text="Character Sequences")
        nibble_label.pack()

    def get_sequence_mining_params(self):
        try:
            parsed_percentage = float(self.percentage_entry.get())
        except ValueError:
            parsed_percentage = 10.0

        if parsed_percentage <= 0 or parsed_percentage >= 100:
            parsed_percentage = 10.0

        try:
            parsed_min_fixed_bits = int(self.min_fixed_bits_entry.get())
        except ValueError:
            parsed_min_fixed_bits = 16

        if parsed_min_fixed_bits < 0:
            parsed_min_fixed_bits = 16

        use_binary = False
        # Add code to check the selection of binary or nibble sequences
        
        Preferences.store()
        
        return SequenceMiningParams(parsed_percentage / 100.0, parsed_min_fixed_bits, use_binary)

class SequenceMiningParams:
    def __init__(self, percentage, min_fix_bits, use_binary):
        self.percentage = percentage
        self.min_fix_bits = min_fix_bits
        self.use_binary = use_binary

# Usage example:

dialog = SequenceMiningParamsInputDialog("Sequence Mining Parameters")
dialog.root.mainloop()

mining_params = dialog.get_sequence_mining_params()
print(mining_params)
