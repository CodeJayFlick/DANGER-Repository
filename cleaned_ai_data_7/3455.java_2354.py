import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class CreateBookmarkDialog:
    def __init__(self, plugin, cu, has_selection):
        self.plugin = plugin
        self.program = plugin.get_current_program()
        self.address = cu.get_min_address()

        self.location_text_field = tk.Text(width=50)
        self.category_combobox = ttk.Combobox(values=self.model())
        self.category_text_field = tk.Entry()
        self.comment_text_field = tk.Text(height=20, width=30)

        if has_selection:
            selection_checkbox = tk.Checkbutton(text="Bookmark Top of Each Selection", state='disabled')
            ranges = plugin.get_program_selection().get_num_address_ranges()

            if ranges > 1:
                selection_checkbox.config(state='normal')

        self.ok_button = tk.Button(text="OK")
        self.cancel_button = tk.Button(text="Cancel")

    def model(self):
        bookmark_manager = self.program.get_bookmark_manager()
        categories = bookmark_manager.get_categories(BookmarkType.NOTE)
        array = [''] + [category for category in categories]
        return sorted(array)

    def populate_display(self, default_comment):
        if default_comment is None:
            default_comment = ''
        else:
            default_comment = default_comment.replace('\n', '  ')

        bookmarks = self.program.get_bookmark_manager().get_bookmarks(self.address, BookmarkType.NOTE)
        if len(bookmarks) != 0:
            category_combobox.set(bookmarks[0].get_category())
            comment_text_field.insert('1.0', bookmarks[0].get_comment())
        else:
            comment_text_field.insert('1.0', default_comment)

    def ok_callback(self):
        text_field = self.category_combobox.get()
        comment = self.comment_text_field.get('1.0', 'end-1c')

        if selection_checkbox.instate()[0]:
            plugin.set_note(None, category, comment)
        else:
            plugin.set_note(address, category, comment)

        cancel_callback()

    def dispose(self):
        self.plugin = None
        self.program = None
        self.address = None

class BookmarkManager:
    def get_categories(self, bookmark_type):
        # implement this method to return the categories for a given bookmark type
        pass

    def get_bookmarks(self, address, bookmark_type):
        # implement this method to return bookmarks at a given address and type
        pass

# usage example
plugin = BookmarkPlugin()
cu = CodeUnit()  # or any other object that has methods like get_min_address(), etc.
has_selection = True  # whether the user selected multiple ranges in the program

dialog = CreateBookmarkDialog(plugin, cu, has_selection)
