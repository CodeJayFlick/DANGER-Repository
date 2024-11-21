from abc import ABCMeta, abstractmethod
import tkinter as tk
from typing import List, Dict, Any, Tuple

class AvailableRegisterTableColumns(metaclass=ABCMeta):
    @abstractmethod
    def get_header(self) -> str:
        pass

    @abstractmethod
    def is_editable(self, row: 'AvailableRegisterRow') -> bool:
        pass

    @abstractmethod
    def is_sortable(self) -> bool:
        pass

class AvailableRegistersTableModel():
    def __init__(self):
        self.columns = [obj for obj in dir(AvailableRegisterTableColumns)]
        super().__init__()

    def default_sort_order(self) -> List['AvailableRegisterTableColumns']:
        return [column for column in self.columns if isinstance(getattr(column, 'NUMBER'), int)]

class AvailableRegisterRow:
    def __init__(self, number: int, register: Any):
        self.number = number
        self.register = register

    @property
    def get_number(self) -> int:
        return self.number

    @property
    def get_name(self) -> str:
        return f"Register {self.number}"

    @property
    def get_bits(self) -> int:
        return 32 if self.register.getBits() == '32' else 64

    @property
    def is_known(self) -> bool:
        return True

    @property
    def get_group(self) -> str:
        return f"Group {self.number}"

    @property
    def get_contains(self) -> str:
        return "Contains: None"

    @property
    def get_parent_name(self) -> str:
        return self.register.getName()

class DebuggerAvailableRegistersDialog():
    def __init__(self, provider):
        super().__init__()
        self.provider = provider

    def populate_components(self):
        panel = tk.Frame()
        available_table = tk.ttk.Treeview(panel)
        available_filter_panel = tk.Frame(panel)

        for column in AvailableRegisterTableColumns.__subclasses__():
            if isinstance(getattr(column, 'NUMBER'), int) or isinstance(getattr(column, 'NAME'), str):
                available_table.column(str(column).split('.')[-1], width=100)
                available_table.heading(str(column).split('.')[-1], text=getattr(column, 'get_header')())

        for row in self.available_model.get_model_data():
            if column.is_editable(row) and isinstance(getattr(column, 'NUMBER'), int):
                available_table.insert('', tk.END, values=[getattr(column, 'get_value_of')(row)] + [str(getattr(column, 'get_name')(row))])

        panel.pack(side=tk.LEFT)
        available_filter_panel.pack(side=tk.BOTTOM)

    def set_available(self, regs: List[Any]):
        self.available_model.clear()
        for i in range(len(regs)):
            reg = regs[i]
            row = AvailableRegisterRow(i, reg)
            self.available_model.add(row)

    def set_language(self, language):
        if self.language == language:
            return
        self.language = language

class DebuggerAvailableRegistersActionContext():
    pass

def create_action_add() -> tk.Button:
    action = tk.Button()
    action.pack(side=tk.LEFT)
    return action

def create_action_remove() -> tk.Button:
    action = tk.Button()
    action.pack(side=tk.RIGHT)
    return action
