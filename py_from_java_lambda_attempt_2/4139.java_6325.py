Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox

class InstructionInfoProvider:
    def __init__(self, plugin, dynamic):
        self.plugin = plugin
        self.dynamic_update_selected = dynamic
        self.main_panel = None
        self.pane = None
        self.instruction_text = None
        self.op_table = None
        self.operand_model = None

    def get_component(self):
        return self.main_panel

    def set_help_location(self, location):
        pass  # No equivalent in Python's tkinter module

    def dynamic_update_selected(self):
        return self.dynamic_update_selected

    def set_status_text(self, msg):
        messagebox.showinfo("Status", msg)

    def dispose(self):
        if hasattr(self, 'program'):
            self.program = None
        if hasattr(self, 'plugin'):
            self.plugin = None
        if hasattr(self, 'tool'):
            self.tool = None

    def build_main_panel(self, dynamic):
        self.main_panel = tk.Frame()
        self.pane = tk.Splitter(orient=tk.HORIZONTAL)
        self.instruction_text = scrolledtext.ScrolledText(self.main_panel)
        font = tk.font.Font(family='monospaced', size=14)
        self.instruction_text.config(font=(font.name, font.size))
        self.instruction_text.config(state='disabled')
        self.operand_model = OperandModel()
        self.op_table = ttk.Treeview(self.main_panel, columns=self.operand_model.get_column_names())
        for column in range(len(self.operand_model.get_column_names())):
            self.op_table.column(column, width=100)
            self.op_table.heading(column, text=self.operand_model.get_column_name(column))
        self.pane.add(tk.Frame(self.main_panel), tk.LEFT)
        self.pane.add(self.instruction_text, tk.RIGHT)
        self.main_panel.pack(fill=tk.BOTH)

    def update_title(self):
        pass  # No equivalent in Python's tkinter module

    def set_program(self, program):
        if hasattr(self, 'operand_model'):
            self.operand_model.set_instruction(None, None)
        if hasattr(self, 'program'):
            self.program.remove_listener(self)
        self.program = program
        if hasattr(self, 'program') and self.program is not None:
            self.program.add_listener(self)

    def show(self):
        pass  # No equivalent in Python's tkinter module

class OperandModel:
    def __init__(self):
        self.instruction = None
        self.debug = None

    def set_instruction(self, instruction, debug):
        self.instruction = instruction
        self.debug = debug
        if hasattr(self, 'tree'):
            for child in self.tree.get_children():
                self.tree.delete(child)
        else:
            pass  # No equivalent in Python's tkinter module

    def get_column_names(self):
        return ['Operand', 'Labeled', 'Type', 'Scalar', 'Address', 'Register', 'Op-Objects', 'Masked Value']

    def get_column_name(self, column_index):
        if column_index == 0:
            return ''
        else:
            return f'Operand-{column_index}'

    def get_row_count(self):
        return 9

    def is_cell_editable(self, row, column):
        return False

class SleighDebugLogger:
    pass  # No equivalent in Python's tkinter module
```

Please note that this translation may not be perfect as the Java code uses some classes and methods which are specific to Java.