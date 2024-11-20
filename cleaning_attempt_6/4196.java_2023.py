import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog

class OffsetTableDialog:
    def __init__(self, default_address):
        self.default_address = default_address
        self.canceled = False
        
    def cancel_callback(self):
        self.canceled = True
        self.close()
        
    def ok_callback(self):
        if self.addr_input.get_address() is not None:
            self.close()
        else:
            self.status_text.set("Please enter a valid address")
            
    def set_selected_size(self, size):
        self.combo_box.set(size)
        
    def show_dialog(self):
        self.canceled = False
        self.show()
        if self.canceled:
            raise CancelledException
            
    def get_selected_size(self):
        return int(self.combo_box.get())
    
    def get_base_address(self):
        return self.addr_input.get_address()
    
    def set_base_address(self, address):
        self.addr_input.set_address(address)
        
    def is_signed(self):
        return self.signed_check_box.instate([tk.ACTIVE])
    
    def set_signed(self, signed):
        self.signed_check_box.config(state=tk.NORMAL if signed else tk.DISABLED)

class AddressInput:
    def __init__(self):
        self.address = None
        self.entry = tk.Entry()
        
    def get_address(self):
        return self.address
        
    def set_address(self, address):
        self.address = address

class OffsetTableDialogGUI(OffsetTableDialog):
    def build_main_panel(self):
        panel = tk.Frame(bg='white')
        addr_input = AddressInput()
        addr_input.entry.insert('end', str(self.default_address))
        
        label1 = tk.Label(panel, text="Enter Base Address:", bg='white')
        label2 = tk.Label(panel, text="Select Data Size (Bytes):", bg='white')

        self.addr_input = addr_input
        self.combo_box = tk.StringVar()
        combo_box_values = ['1', '2', '4', '8']
        self.combo_box.set(combo_box_values[0])
        
        signed_check_box = tk.BooleanVar(value=True)
        self.signed_check_box = tk.Checkbutton(panel, text="Signed Data Value(s)", variable=signed_check_box)

        panel.grid_columnconfigure(1, weight=1)
        label1.grid(row=0, column=0, sticky='w')
        addr_input.entry.grid(row=0, column=1, sticky='ew')
        self.combo_box.set(combo_box_values[0])
        combo_box = tk.OptionMenu(panel, self.combo_box, *combo_box_values)
        combo_box.grid(row=1, column=0, columnspan=2)

        signed_check_box.set(signed=True)
        panel.add(self.signed_check_box, row=2, column=0, columnspan=2)

    def close(self):
        if self.canceled:
            messagebox.showinfo("Offset Table Dialog", "Dialog was canceled")
            
def main():
    default_address = 123456789
    dialog = OffsetTableDialogGUI(default_address)
    try:
        dialog.build_main_panel()
    except CancelledException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

