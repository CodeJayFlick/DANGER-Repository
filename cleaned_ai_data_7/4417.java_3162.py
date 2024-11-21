import tkinter as tk
from tkinter import ttk
from typing import List

class ValidateProgramDialog:
    def __init__(self, program: str, condition_testers: List):
        self.condition_test_panel = ConditionTestPanel(condition_testers)

        main_frame = tk.Frame()
        main_frame.pack(fill="both", expand=True)
        
        self.condition_test_panel.pack(side=tk.LEFT, fill="both", expand=True)

        run_button_frame = tk.Frame(main_frame)
        run_button_frame.pack(side=tk.BOTTOM, fill="x")

        run_tests_button = ttk.Button(run_button_frame, text="Run Validators")
        run_tests_button['command'] = lambda: self.condition_test_panel.run_tests()
        run_tests_button.pack(fill='both', expand=True)

    def get_title(self) -> str:
        return f"Validate: {program.get_domain_file().get_name()}"

class ConditionTestPanel:
    def __init__(self, condition_testers):
        pass

    def set_border(self, border_width=10):
        self.border = tk.Frame()
        self.border.pack(side=tk.LEFT, fill="both", expand=True)

    def run_tests(self):
        # implement the logic for running tests
        pass

class Program:
    def __init__(self, domain_file_name: str):
        self.domain_file_name = domain_file_name

    def get_domain_file(self) -> 'DomainFile':
        return DomainFile(self.domain_file_name)

class DomainFile:
    def __init__(self, name: str):
        self.name = name

    def get_name(self) -> str:
        return self.name
