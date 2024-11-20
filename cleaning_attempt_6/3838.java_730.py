from abc import ABCMeta, abstractmethod
import tkinter as tk
from tkinter import messagebox

class AbstractEditFunctionSignatureDialog:
    def __init__(self, tool, title, allow_in_line, allow_no_return, allow_call_fixup):
        self.tool = tool
        self.allow_in_line = allow_in_line
        self.allow_no_return = allow_no_return
        self.allow_call_fixup = allow_call_fixup

        super().__init__()
        self.title(title)
        self.geometry("300x200")
        self.create_widgets()

    def create_widgets(self):
        panel = tk.Frame(self, borderwidth=5)
        panel.pack(fill="both", expand=True)

        signature_label = tk.Label(panel, text="Signature:")
        signature_label.grid(row=0, column=0, padx=(10, 0), pady=(10, 0))
        self.signature_field = tk.Entry(panel, width=60)
        self.signature_field.grid(row=1, column=0, padx=(10, 0), pady=(5, 0))

        if self.allow_call_fixup:
            call_fixup_label = tk.Label(panel, text="Call-Fixup:")
            call_fixup_label.grid(row=2, column=0, padx=(10, 0), pady=(5, 0))
            self.call_fixup_combobox = tk.StringVar()
            self.call_fixup_combobox.set("-NONE-")
            self.call_fixup_comboboxCombobox = ttk.Combobox(panel, textvariable=self.call_fixup_combobox)
            self.call_fixup_comboboxCombobox.grid(row=3, column=0, padx=(10, 0), pady=(5, 0))

        if self.allow_in_line:
            inline_checkbox = tk.IntVar()
            inline_checkbox.set(1) # Set to checked by default
            inline_checkboxCheckbutton = ttk.Checkbutton(panel, text="Inline", variable=inline_checkbox)
            inline_checkboxCheckbutton.grid(row=4, column=0, padx=(10, 0), pady=(5, 0))

        if self.allow_no_return:
            no_return_checkbox = tk.IntVar()
            no_return_checkbox.set(1) # Set to checked by default
            no_return_checkboxCheckbutton = ttk.Checkbutton(panel, text="No Return", variable=no_return_checkbox)
            no_return_checkboxCheckbutton.grid(row=5, column=0, padx=(10, 0), pady=(5, 0))

        self.ok_button = tk.Button(self, text="OK")
        self.ok_button.pack(fill="x")

    def apply_changes(self):
        # To be implemented
        pass

    def parse_signature(self):
        try:
            return FunctionDefinitionDataType()  # Replace with actual parsing logic
        except ParseException as e:
            messagebox.showerror("Error", "Invalid Signature: " + str(e))

    def is_signature_changed(self):
        return self.signature_field.get().lower() != get_prototype_string()

    def is_calling_convention_changed(self):
        current = get_calling_convention_name()
        if current == None and self.call_fixup_combobox.get().lower() == "-none-":
            return False
        if current == None and self.call_fixup_combobox.get().lower() == "default":
            return False
        if current == None:
            return True
        if current.lower() == self.call_fixup_combobox.get():
            return False
        return True

    def dialog_shown(self):
        self.signature_field.focus_set()

class FunctionDefinitionDataType(metaclass=ABCMeta):
    @abstractmethod
    def parse(self, signature: str) -> None:
        pass

def get_prototype_string() -> str:
    # To be implemented
    pass

def get_calling_convention_name() -> str:
    # To be implemented
    pass
