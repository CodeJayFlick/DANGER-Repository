import tkinter as tk
from tkinter import filedialog
from tkinter.messagebox import showinfo

class SearchStringDialog:
    def __init__(self, plugin, address_set):
        self.plugin = plugin
        self.address_set = address_set
        
        # Create main window
        self.main_window = tk.Tk()
        self.main_window.title("Search For Strings")
        
        # Create panel for options on the left side of the main panel
        self.options_panel_left = tk.Frame(self.main_window)
        self.options_panel_left.pack(side=tk.LEFT, fill=tk.Y)

        # Create panel for options on the right side of the main panel
        self.options_panel_right = tk.Frame(self.main_window)
        self.options_panel_right.pack(side=tk.RIGHT, fill=tk.Y)

        # Create memory blocks panel
        self.memory_blocks_panel = tk.Frame(self.main_window)
        self.memory_blocks_panel.pack(fill=tk.X)

        # Create selection scope panel
        self.selection_scope_panel = tk.Frame(self.main_window)
        self.selection_scope_panel.pack(fill=tk.X)

    def ok_callback(self):
        try:
            min_length = int(self.min_length_field.get())
            if min_length <= 1:
                showinfo("Error", "Please enter a valid minimum search length. Must be > 1")
                return

            options = StringTableOptions()
            options.set_alignment(int(self.alignment_field.get()))
            options.set_min_string_size(min_length)
            options.set_null_termination_required(self.null.terminate_checkbox_var.get())
            options.set_require_pascal(self.pascal_strings_checkbox_var.get())

            if self.search_selection_rb_var.get():
                options.set_address_set(self.address_set)

            word_model_file = self.word_model_field.get()
            
            if not word_model_file:
                options.set_word_model_initialized(False)
            else:
                try:
                    NGramUtils.start_new_session(word_model_file, False)
                    options.set_word_model_initialized(True)
                    options.set_word_model_file(word_model_file)
                except IOException as e:
                    showinfo("Error", "Select a valid model file (e.g., 'StringModel.sng') or leave blank.")
                    return

            self.plugin.create_strings_provider(options)
            self.main_window.destroy()

    def build_options_panel_left(self):
        panel = tk.Frame()
        panel.pack(fill=tk.X)

        null_terminate_checkbox_var = tk.IntVar()
        pascal_strings_checkbox_var = tk.IntVar()

        null_terminate_checkbox = tk.Checkbutton(panel, text="Require Null Termination", variable=null_terminate_checkbox_var)
        pascal_strings_checkbox = tk.Checkbutton(panel, text="Pascal Strings", variable=pascal_strings_checkbox_var)

        panel.pack(fill=tk.X)

    def build_options_panel_right(self):
        panel = tk.Frame()
        panel.pack(fill=tk.X)

        min_length_label = tk.Label(panel, text="Minimum Length:")
        self.min_length_field = tk.Entry(panel)
        
        alignment_label = tk.Label(panel, text="Alignment:")
        self.alignment_field = tk.Entry(panel)

    def create_model_field_panel(self):
        model_label = tk.Label()
        model_label.pack(fill=tk.X)

        word_model_field = tk.Entry()

        browse_button = tk.Button(text="Browse")
        browse_button.config(command=lambda: filedialog.askopenfilename())

        panel.pack(fill=tk.X)

    def build_memory_blocks_panel(self):
        panel = tk.Frame()
        panel.pack(fill=tk.X)

        loaded_blocks_rb_var = tk.IntVar()
        all_blocks_rb_var = tk.IntVar()

        loaded_blocks_rb = tk.Radiobutton(panel, text="Loaded Blocks", variable=loaded_blocks_rb_var)
        all_blocks_rb = tk.Radiobutton(panel, text="All Blocks", variable=all_blocks_rb_var)

    def build_selection_scope_panel(self):
        panel = tk.Frame()
        panel.pack(fill=tk.X)

        search_all_rb_var = tk.IntVar()
        search_selection_rb_var = tk.IntVar()

        search_all_rb = tk.Radiobutton(panel, text="Search All", variable=search_all_rb_var)
        search_selection_rb = tk.Radiobutton(panel, text="Search Selection", variable=search_selection_rb_var)

    def has_selection(self):
        return self.address_set is not None and not self.address_set.empty()

class StringTableOptions:
    # Add your own attributes here
    pass

# Create the main window
main_window = SearchStringDialog(plugin, address_set)
