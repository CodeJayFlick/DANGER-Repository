Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog
from tkinter.messagebox import showerror

class PopulateFidDialog:
    def __init__(self, tool):
        self.tool = tool
        self.fid_service = None
        self.library_family_name_textfield = None
        self.version_textfield = None
        self.variant_textfield = None
        self.domain_folder_field = None
        self.fid_file_combobox = None
        self.library_combobox = None
        self.language_id_field = None
        self.symbols_file_textfield = None

    def ok_callback(self):
        fid_file = self.fid_file_combobox.get()
        library_choice = self.library_combobox.get()
        library_record = library_choice[1]
        library_family_name = self.library_family_name_textfield.get().strip()
        version = self.version_textfield.get().strip()
        variant = self.variant_textfield.get().strip()
        domain_folder = get_domain_folder(self.tool)
        language_filter = self.language_id_field.get().strip()
        common_symbols_file = get_common_symbols_file()

        task = Task("Populate Library Task", fid_file, library_record, domain_folder,
                    library_family_name, version, variant, language_filter, common_symbols_file,
                    self.fid_service, DefaultFidPopulateResultReporter())
        close()
        self.tool.execute(task)

    def get_common_symbols_file(self):
        symbols_file_path = self.symbols_file_textfield.get().strip()
        if not symbols_file_path:
            return None
        return File(symbols_file_path)

    def build_main_panel(self):
        panel = tk.Frame()
        panel.pack(fill=tk.BOTH, expand=1)
        label = tk.Label(panel, text="Fid Database:")
        label.grid(row=0, column=0, sticky='w')
        self.fid_file_combobox = GComboBox()
        self.fid_file_combobox.set_values(FidFileManager().get_user_added_files())
        panel.add(self.fid_file_combobox)

        tk.Label(panel, text="Library Family Name:").grid(row=1, column=0)
        self.library_family_name_textfield = tk.Entry(width=20)
        self.library_family_name_textfield.insert(0, '')
        self.library_family_name_textfield.bind("<KeyRelease>", lambda e: update_ok_enablement())
        panel.add(self.library_family_name_textfield)

        tk.Label(panel, text="Library Version:").grid(row=2, column=0)
        self.version_textfield = tk.Entry(width=20)
        self.version_textfield.insert(0, '')
        self.version_textfield.bind("<KeyRelease>", lambda e: update_ok_enablement())
        panel.add(self.version_textfield)

        tk.Label(panel, text="Library Variant:").grid(row=3, column=0)
        self.variant_textfield = tk.Entry(width=20)
        self.variant_textfield.insert(0, '')
        self.variant_textfield.bind("<KeyRelease>", lambda e: update_ok_enablement())
        panel.add(self.variant_textfield)

        tk.Label(panel, text="Base Library:").grid(row=4, column=0)
        self.library_combobox = GComboBox()
        self.build_library_combo()

        tk.Label(panel, text="Root Folder:").grid(row=5, column=0)
        self.domain_folder_field = tk.Entry(width=20)
        self.domain_folder_field.insert(0, '')
        panel.add(self.domain_folder_field)

        tk.Button(panel, text='Browse', command=lambda: browse_domain_folder()).pack(side=tk.RIGHT)

        tk.Label(panel, text="Language:").grid(row=6, column=0)
        self.language_id_field = tk.Entry(width=20)
        self.language_id_field.insert(0, '')
        panel.add(self.language_id_field)

        tk.Button(panel, text='Browse', command=lambda: browse_language()).pack(side=tk.RIGHT)

        tk.Label(panel, text="Common Symbols File:").grid(row=7, column=0)
        self.symbols_file_textfield = tk.Entry(width=20)
        self.symbols_file_textfield.insert(0, '')
        panel.add(self.symbols_file_textfield)

        tk.Button(panel, text='Browse', command=lambda: browse_symbols_file()).pack(side=tk.RIGHT)

    def build_library_combo(self):
        choices = get_choices_for_library_combo()
        self.library_combobox.set_values(choices)
        return

    def update_ok_enablement(self):
        set_ok_enabled(is_user_input_complete())

    def is_user_input_complete(self):
        if not self.fid_file_combobox.get():
            return False
        if not self.library_family_name_textfield.get().strip():
            return False
        if not self.version_textfield.get().strip():
            return False
        if not self.variant_textfield.get().strip():
            return False
        if not self.domain_folder_field.get().strip():
            return False
        if not self.language_id_field.get().strip():
            return False
        symbols_file_path = self.symbols_file_textfield.get().strip()
        if symbols_file_path and not File(symbols_file_path).exists:
            return False
        return True

    def create_browse_button(self):
        button = tk.Button(text='Browse')
        font = button.cget('font')
        button.config(font=(font[0], font[1] + 2))
        return button

class LibraryChoice:
    def __init__(self, name, library_record):
        self.name = name
        self.library_record = library_record

    def __str__(self):
        return self.name

def get_domain_folder(self):
    # implement this method to get the domain folder
    pass

def get_common_symbols_file():
    symbols_file_path = ''
    if not symbols_file_path:
        return None
    return File(symbols_file_path)

class Task:
    def __init__(self, name, fid_file, library_record, domain_folder,
                 library_family_name, version, variant, language_filter, common_symbols_file,
                 fid_service, result_reporter):
        self.name = name
        self.fid_file = fid_file
        self.library_record = library_record
        self.domain_folder = domain_folder
        self.library_family_name = library_family_name
        self.version = version
        self.variant = variant
        self.language_filter = language_filter
        self.common_symbols_file = common_symbols_file
        self.fid_service = fid_service
        self.result_reporter = result_reporter

    def execute(self):
        # implement this method to execute the task
        pass

class DefaultFidPopulateResultReporter:
    def __init__(self):
        pass

    def report_results(self, results):
        # implement this method to report the results
        pass