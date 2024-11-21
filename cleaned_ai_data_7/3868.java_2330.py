class StorageAddressModel:
    def __init__(self, program: 'Program', storage: 'VariableStorage', listener):
        self.listener = listener
        self.program = program
        
        if storage is not None:
            for varnode in storage.getVarnodes():
                self.varnodes.append(VarnodeInfo(program, varnode))
        
    def add_varnode(self):
        self.listener.table_rows_changed()
        self.varnodes.append(VarnodeInfo(self.program, VarnodeType.Register))
        selected_row = len(self.varnodes) - 1
        notify_data_changed()

    def remove_varnodes(self):
        if not can_remove_varnodes():
            raise AssertException("Attempted to remove varnodes when not allowed.")
        
        self.listener.table_rows_changed()
        sorted_selected_rows = sorted(selected_varnode_rows)
        for i in range(len(sorted_selected_rows) - 1, -1, -1):
            index = selected_varnode_rows[i]
            self.varnodes.remove(index)
        
        if len(self.varnodes) == 0:
            selected_varnode_rows = [0]
        else:
            select_row = min(selected_varnode_rows[0], len(self.varnodes) - 1)
            selected_varnode_rows = [select_row]
        
        notify_data_changed()

    def move_selected_varnode_up(self):
        if not can_move_varnode_up():
            raise AssertException("Attempted to move a varnode up when not allowed.")
        
        self.listener.table_rows_changed()
        index = selected_varnode_rows[0]
        info = self.varnodes.pop(index)
        self.varnodes.insert(index - 1, info)
        set_selected_row(index - 1)
        notify_data_changed()

    def move_selected_varnode_down(self):
        if not can_move_varnode_down():
            raise AssertException("Attempted to move a varnode down when not allowed.")
        
        self.listener.table_rows_changed()
        index = selected_varnode_rows[0]
        info = self.varnodes.pop(index)
        self.varnodes.insert(index + 1, info)
        set_selected_row(index + 1)
        notify_data_changed()

    def get_varnodes(self):
        return self.varnodes

    def set_required_size(self, required_size: int, unconstrained: bool):
        self.required_size = required_size
        self.unconstrained = unconstrained
        validate()

    def get_required_size(self):
        return self.required_size

    def is_unconstrained(self):
        return self.unconstrained

    def get_current_size(self):
        size = 0
        for varnode in self.varnodes:
            if varnode.get_size() is not None:
                size += varnode.get_size()
        
        return size

    def get_status_text(self):
        return self.status_text

    def is_valid(self):
        return self.is_valid

    def set_selected_varnoderows(self, selected_rows: list):
        self.selected_varnode_rows = selected_rows
        notify_data_changed()

    def set_selected_row(self, row: int):
        self.selected_varnode_rows = [row]

    def get_selected_varnode_rows(self):
        return self.selected_varnode_rows

    # ... (rest of the methods)

class VarnodeInfo:
    def __init__(self, program: 'Program', varnode):
        self.program = program
        self.varnode = varnode

    def set_address(self, address: Address):
        pass  # implement this method

    def get_size(self) -> int:
        return self.size

    def set_size(self, size: int):
        self.size = size

class Program:
    def __init__(self):
        pass  # implement this class

class VariableStorage:
    VOID_STORAGE = None
    UNASSIGNED_STORAGE = None

    def __init__(self, program: 'Program', varnodes: list):
        pass  # implement this class

def notify_data_changed():
    validate()
    SwingUtilities.invokeLater(lambda: listener.data_changed())

def can_remove_varnodes() -> bool:
    return len(selected_varnode_rows) > 0

def can_move_varnode_up() -> bool:
    return len(selected_varnode_rows) == 1 and selected_varnode_rows[0] > 0

def can_move_varnode_down() -> bool:
    return len(selected_varnode_rows) == 1 and selected_varnode_rows[0] < len(self.varnodes) - 1
