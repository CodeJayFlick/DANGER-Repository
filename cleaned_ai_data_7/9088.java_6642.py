from tkinter import *
import ghidra_app_util as app_util
import ghidra_program_model_address as program_model_address
import ghidra_program_model_listing as program_model_listing
import ghidra_util_layout as util_layout

class AddRemoveAddressRangeDialog:
    def __init__(self, type, program_indicator, program, listener):
        self.program = program
        self.address_factory = program.get_address_factory()
        self.listener = listener
        
        root = Tk()
        root.title(program_indicator + " Address Range")
        
        address_range_panel = Frame(root)
        address_range_panel.pack(fill=BOTH, expand=1)

        min_label = Label(address_range_panel, text="Minimum:")
        max_label = Label(address_range_panel, text="Maximum:")

        self.min_address_field = Entry(address_range_panel)
        self.max_address_field = Entry(address_range_panel)

        for widget in [min_label, max_label]:
            widget.pack(side=LEFT, padx=5, pady=2)

        for field in [self.min_address_field, self.max_address_field]:
            field.pack(side=LEFT, padx=5, expand=True)
        
        root.mainloop()

    def create_address_range_panel(self):
        return address_range_panel

    def dialog_shown(self):
        pass  # No equivalent method in Python's Tkinter library.

    def ok_callback(self):
        if self.is_valid_range():
            if self.listener is not None:
                self.listener.process_address_range(self.get_min_address(), self.get_max_address())
            root.destroy()

    def is_valid_range(self):
        min_address = self.min_address_field.get()
        max_address = self.max_address_field.get()

        if not min_address or not max_address:
            return False

        try:
            min_addr = program_model_address.Address(min_address)
            max_addr = program_model_address.Address(max_address)

            if min_addr > max_addr:
                return False
        except Exception as e:
            print(f"Error: {e}")
            return False
        
        return True

    def get_min_address(self):
        return self.min_address_field.get()

    def get_max_address(self):
        return self.max_address_field.get()
