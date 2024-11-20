import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Set, List

class ProcessorListPlugin:
    def __init__(self):
        self.processor_list_action = None
        self.dialog_provider = None

    def setup_actions(self):
        if not hasattr(self, 'processor_list_action'):
            self.processor_list_action = tk.Button(text="Installed Processors", command=self.show_processor_list)
            self.processor_list_action.pack()

    def dispose(self):
        pass  # No equivalent in Python for disposing of actions

    def show_processor_list(self):
        if self.dialog_provider is None:
            self.dialog_provider = ProcessorListDialogProvider()
        self.dialog_provider.display()

class ProcessorListDialogProvider:
    def __init__(self, owner=None):
        super().__init__()
        self.owner = owner
        self.build_table()

    def build_table(self):
        processors: Set[Processor] = set()  # No equivalent in Python for TreeSet
        language_service = DefaultLanguageService()
        for lang_description in language_service.get_language_descriptions():
            processors.add(lang_description.processor)

class ProcessorListTableModel:
    PROCESSOR_COL = 0

    def __init__(self, processors: List[Processor]):
        self.processors = processors

    def get_column_value_for_row(self, p: Processor, column_index: int):
        if column_index == self.PROCESSOR_COL:
            return str(p)
        else:
            return None
