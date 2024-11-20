import tkinter as tk
from tkinter import messagebox
from typing import Collection, List

class ImporterLanguageDialog:
    def __init__(self, load_specs: Collection, tool=None, default_selected_language=None):
        self.load_specs = load_specs
        self.tool = tool
        self.default_selected_language = default_selected_language
        self.was_dialog_cancelled = False
        self.language_panel = None

    def show(self, parent):
        if tkinter.get_current_exception():
            self.build()
            self.tool.show_dialog(self, parent)
        else:
            try:
                tkinter.invoke(lambda: (self.build(), self.tool.show_dialog(self, parent)), check=True)
            except Exception as e:
                messagebox.error("Error", str(e))

    def build(self):
        self.language_panel = NewLanguagePanel()
        self.language_panel.set_recommended_lcs_pairs_list([])
        self.language_panel.set_show_all_lcs_pairs(False)
        self.language_panel.set_border(tkinter.ttk.Frame().create_titledBorder("Select Language and Compiler Specification"))
        self.language_panel.add_selection_listener(LcsSelectionListener())
        self.initialize()

    def initialize(self):
        pairs = ImporterUtilities.get_pairs(self.load_specs)
        self.language_panel.set_recommended_lcs_pairs_list(pairs)
        self.language_panel.set_show_all_lcs_pairs(len(pairs) == 0)
        self.language_panel.setEnabled(True)

        if self.default_selected_language is not None:
            self.language_panel.set_selected_lcs_pair(self.default_selected_language)
        else:
            select_preferred_language()

    def ok_callback(self):
        if validate_form_input():
            close()
        else:
            messagebox.showerror("Error", "Please select a language.")

    def cancel_callback(self):
        self.was_dialog_cancelled = True
        super().cancel_callback()

    def get_selected_language(self) -> LanguageCompilerSpecPair:
        return self.language_panel.get_selected_lcs_pair() if not self.was_dialog_cancelled else None

class NewLanguagePanel:
    pass  # implement this class as per your requirements

class LcsSelectionListener:
    pass  # implement this class as per your requirements
