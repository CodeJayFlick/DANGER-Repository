Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import StringVar, IntVar

class DataOrganizationPanel:
    def __init__(self):
        self.data_organization = None
        
        # Create GUI components
        self.char_is_signed_checkbox = tk.BooleanVar()
        self.char_size_component = tk.Entry()
        self.wchar_size_component = tk.Entry()
        self.short_size_component = tk.Entry()
        self.integer_size_component = tk.Entry()
        self.long_size_component = tk.Entry()
        self.long_long_size_component = tk.Entry()
        self.float_size_component = tk.Entry()
        self.double_size_component = tk.Entry()
        self.long_double_size_component = tk.Entry()

        self.absolute_max_align_component = tk.Entry()
        self.machine_align_component = tk.Entry()
        self.default_align_component = tk.Entry()
        self.pointer_align_component = tk.Entry()

    def set_organization(self, data_organization):
        if data_organization is not None:
            self.data_organization = data_organization

            # Update GUI components with the organization settings
            char_size = str(data_organization.get_char_size())
            wchar_size = str(data_organization.get_wide_char_size())
            short_size = str(data_organization.get_short_size())
            integer_size = str(data_organization.get_integer_size())
            long_size = str(data_organization.get_long_size())
            long_long_size = str(data_organization.get_long_long_size())
            float_size = str(data_organization.get_float_size())
            double_size = str(data_organization.get_double_size())
            long_double_size = str(data_organization.get_long_double_size())

            absolute_max_alignment = data_organization.get_absolute_max_alignment()
            machine_alignment = data_organization.get_machine_alignment()
            default_alignment = data_organization.get_default_alignment()
            pointer_alignment = data_organization.get_default_pointer_alignment()

            self.char_is_signed_checkbox.set(str(data_organization.is_char_signed()))
            self.char_size_component.delete(0, tk.END)
            self.char_size_component.insert(0, char_size)

            self.wchar_size_component.delete(0, tk.END)
            self.wchar_size_component.insert(0, wchar_size)

            self.short_size_component.delete(0, tk.END)
            self.short_size_component.insert(0, short_size)

            self.integer_size_component.delete(0, tk.END)
            self.integer_size_component.insert(0, integer_size)

            self.long_size_component.delete(0, tk.END)
            self.long_size_component.insert(0, long_size)

            self.long_long_size_component.delete(0, tk.END)
            self.long_long_size_component.insert(0, long_long_size)

            self.float_size_component.delete(0, tk.END)
            self.float_size_component.insert(0, float_size)

            self.double_size_component.delete(0, tk.END)
            self.double_size_component.insert(0, double_size)

            self.long_double_size_component.delete(0, tk.END)
            self.long_double_size_component.insert(0, long_double_size)

            if absolute_max_alignment == 0:
                max_align_string = "none"
            else:
                max_align_string = str(absolute_max_alignment)

            self.absolute_max_align_component.delete(0, tk.END)
            self.absolute_max_align_component.insert(0, max_align_string)

            self.machine_align_component.delete(0, tk.END)
            self.machine_align_component.insert(0, machine_alignment)

            self.default_align_component.delete(0, tk.END)
            self.default_align_component.insert(0, default_alignment)

            self.pointer_align_component.delete(0, tk.END)
            self.pointer_align_component.insert(0, pointer_alignment)

    def update_signed_char(self):
        if self.data_organization is not None:
            self.data_organization.set_char_is_signed(self.char_is_signed_checkbox.get())

    def updated_char_size(self):
        if self.data_organization is not None and self.char_size_component.get():
            try:
                char_size = int(self.char_size_component.get())
                self.data_organization.set_char_size(char_size)
            except ValueError:
                pass

    def updated_wide_char_size(self):
        if self.data_organization is not None and self.wchar_size_component.get():
            try:
                wchar_size = int(self.wchar_size_component.get())
                self.data_organization.set_wide_char_size(wchar_size)
            except ValueError:
                pass

    def updated_short_size(self):
        if self.data_organization is not None and self.short_size_component.get():
            try:
                short_size = int(self.short_size_component.get())
                self.data_organization.set_short_size(short_size)
            except ValueError:
                pass

    def updated_integer_size(self):
        if self.data_organization is not None and self.integer_size_component.get():
            try:
                integer_size = int(self.integer_size_component.get())
                self.data_organization.set_integer_size(integer_size)
            except ValueError:
                pass

    def updated_long_size(self):
        if self.data_organization is not None and self.long_size_component.get():
            try:
                long_size = int(self.long_size_component.get())
                self.data_organization.set_long_size(long_size)
            except ValueError:
                pass

    def updated_long_long_size(self):
        if self.data_organization is not None and self.long_long_size_component.get():
            try:
                long_long_size = int(self.long_long_size_component.get())
                self.data_organization.set_long_long_size(long_long_size)
            except ValueError:
                pass

    def updated_float_size(self):
        if self.data_organization is not None and self.float_size_component.get():
            try:
                float_size = int(self.float_size_component.get())
                self.data_organization.set_float_size(float_size)
            except ValueError:
                pass

    def updated_double_size(self):
        if self.data_organization is not None and self.double_size_component.get():
            try:
                double_size = int(self.double_size_component.get())
                self.data_organization.set_double_size(double_size)
            except ValueError:
                pass

    def updated_long_double_size(self):
        if self.data_organization is not None and self.long_double_size_component.get():
            try:
                long_double_size = int(self.long_double_size_component.get())
                self.data_organization.set_long_double_size(long_double_size)
            except ValueError:
                pass

    def updated_absolute_max_alignment(self):
        if self.data_organization is not None and self.absolute_max_align_component.get().lower() != "none":
            try:
                absolute_max_alignment = int(self.absolute_max_align_component.get())
                self.data_organization.set_absolute_max_alignment(absolute_max_alignment)
            except ValueError:
                pass

    def updated_machine_alignment(self):
        if self.data_organization is not None and self.machine_align_component.get():
            try:
                machine_alignment = int(self.machine_align_component.get())
                self.data_organization.set_machine_alignment(machine_alignment)
            except ValueError:
                pass

    def updated_default_alignment(self):
        if self.data_organization is not None and self.default_align_component.get():
            try:
                default_alignment = int(self.default_align_component.get())
                self.data_organization.set_default_alignment(default_alignment)
            except ValueError:
                pass

    def updated_default_pointer_alignment(self):
        if self.data_organization is not None and self.pointer_align_component.get():
            try:
                pointer_alignment = int(self.pointer_align_component.get())
                self.data_organization.set_default_pointer_alignment(pointer_alignment)
            except ValueError:
                pass
```

This Python code creates a GUI with various text fields for the organization settings. The `set_organization` method updates these fields based on the provided data organization object, and vice versa when you call other methods like `update_signed_char`, etc., which update the corresponding values in the data organization object.