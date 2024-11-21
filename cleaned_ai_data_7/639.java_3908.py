import collections
from typing import Dict, Set

class DbgReadRegistersCommand:
    def __init__(self, manager: object, thread: object, frame_id: int, regs: Set):
        self.manager = manager
        self.thread = thread
        self.regs = regs
        self.registers = None
        self.previous_thread_id = None

    def complete(self) -> Dict[object, int]:
        if not self.regs:
            return {}
        result = collections.OrderedDict()
        for r in self.regs:
            if self.registers is not None:
                value = self.registers.get_value_by_name(r.name)
                if value is not None:
                    bval = int.from_bytes(value.encode_as_bytes(), 'big')
                    result[r] = bval
        return result

    def invoke(self):
        previous_thread_id = self.manager.system_objects.current_thread_id()
        self.manager.system_objects.set_current_thread_id(self.thread.id)
        self.registers = self.manager.client.get_registers()

class DbgRegister:
    pass  # assume this class exists in the Python codebase

class DebugRegisters:
    def get_value_by_name(self, name: str) -> object:
        pass  # assume this method is implemented elsewhere
