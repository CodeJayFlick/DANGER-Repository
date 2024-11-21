import tkinter as tk
from tkinter import messagebox
from tkinter import font as tkfont
from tkinter import ttk

class PrintOptionsDialog:
    def __init__(self, selection_enabled):
        self.selection_enabled = selection_enabled
        self.cancelled = False
        
        self.outer_panel = tk.Frame()
        
        self.range_panel = tk.Frame(self.outer_panel)
        self.header_panel = tk.Frame(self.outer_panel)
        self.options_panel = tk.Frame(self.outer_panel)

        self.outer_panel.pack(fill='both', expand=True)
        self.range_panel.pack(side=tk.TOP, fill='x')
        self.header_panel.pack(side=tk.TOP, fill='x')
        self.options_panel.pack(side=tk.BOTTOM, fill='x')

        self.create_widgets()

    def create_widgets(self):
        for widget in [self.range_panel, self.header_panel, self.options_panel]:
            tk.Label(widget, text="").pack(fill='x', padx=5)

        self.selection = ttk.Checkbutton(self.range_panel, text="Selected area(s)")
        self.visible = ttk.Checkbutton(self.range_panel, text="Code visible on screen")
        self.view = ttk.Checkbutton(self.range_panel, text="Current view")

        for button in [self.selection, self.visible, self.view]:
            button.pack(side=tk.LEFT)
        
        self.title = tk.BooleanVar()
        self.date = tk.BooleanVar()
        self.page_num = tk.BooleanVar()

        self.title_checkbox = tk.Checkbutton(self.header_panel, variable=self.title, text="Title")
        self.date_checkbox = tk.Checkbutton(self.header_panel, variable=self.date, text="Date/Time")
        self.page_num_checkbox = tk.Checkbutton(self.header_panel, variable=self.page_num, text="Page Numbers")

        for checkbox in [self.title_checkbox, self.date_checkbox, self.page_num_checkbox]:
            checkbox.pack(side=tk.LEFT)

        self.monochrome = tk.BooleanVar()
        self.monochrome_checkbox = tk.Checkbutton(self.options_panel, variable=self.monochrome, text="Use Monochrome", onvalue=True, offvalue=False)
        
        self.monochrome_checkbox.pack()

    def get_selection(self):
        return self.selection.instate()[1]

    def get_visible(self):
        return self.visible.instate()[1]

    def get_view(self):
        return self.view.instate()[1]

    def get_print_title(self):
        return self.title.get()

    def get_print_date(self):
        return self.date.get()

    def get_print_page_num(self):
        return self.page_num.get()

    def is_cancelled(self):
        return self.cancelled

    def set_selection_enabled(self, selection_enabled):
        if not selection_enabled:
            self.view.select()
        else:
            self.selection.deselect()
            self.visible.deselect()
            self.view.deselect()
        
        self.outer_panel.update_idletasks()

    def show_header(self):
        return self.get_print_title()

    def show_footer(self):
        return self.get_print_date() or self.get_print_page_num()

    def get_monochrome(self):
        return self.monochrome.get()

    def get_header_height(self):
        font = tkfont.Font(family='Sans', size=10)
        ascent, descent = font.metrics('linespace')
        return ascent + descent

root = tk.Tk()
dialog = PrintOptionsDialog(True)

def ok_callback():
    dialog.outer_panel.destroy()

def cancel_callback():
    global cancelled
    cancelled = True
    dialog.outer_panel.destroy()

ok_button = ttk.Button(root, text="OK", command=ok_callback)
cancel_button = ttk.Button(root, text="Cancel", command=cancel_callback)

root.mainloop()
