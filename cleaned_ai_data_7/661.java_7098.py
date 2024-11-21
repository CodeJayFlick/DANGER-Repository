import collections
from typing import Dict, Any

class DbgWriteRegistersCommand:
    def __init__(self, manager: Any, thread: Any, frame_id: int, reg_vals: Dict[Any, int]):
        self.manager = manager
        self.thread = thread
        self.reg_vals = reg_vals

    def invoke(self):
        so = self.manager.get_system_objects()
        previous_thread_id = so.current_thread_id
        so.set_current_thread_id(self.thread.id)
        registers = self.manager.get_registers()
        values = collections.OrderedDict()

        for r in self.reg_vals:
            try:
                val = self.reg_vals[r]
                desc = registers.get_description(r.number)
                bytes = bytearray(desc.type.byte_length)
                new_bytes = val.to_bytes(val.bit_length())
                j = len(bytes) - 1
                i = len(new_bytes) - 1

                while i >= 0 and j >= 0:
                    bytes[j] = new_bytes[i]
                    i -= 1
                    j -= 1

                dv = desc.type.decode_bytes(bytes)
                values[r.number] = dv
            except Exception as e:
                self.manager.get_control().errln(f"No register: {r.name}")

        registers.set_values(DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE, values)
        so.set_current_thread_id(previous_thread_id)

class DbgThreadImpl:
    def __init__(self):
        pass

    @property
    def id(self) -> int:
        return 0  # Replace with actual ID implementation

class DebugSystemObjects:
    def __init__(self):
        pass

    @property
    def current_thread_id(self) -> Any:
        return None  # Replace with actual thread ID implementation

    def set_current_thread_id(self, thread_id: int):
        pass  # Replace with actual implementation to set the current thread ID

class DebugRegisters:
    def __init__(self):
        pass

    @property
    def get_description(self) -> Any:
        return None  # Replace with actual description implementation

    def set_values(self, source: str, values: Dict[Any, int]):
        pass  # Replace with actual implementation to set the register values

class DebugRegisterDescription:
    def __init__(self):
        pass

    @property
    def type(self) -> Any:
        return None  # Replace with actual type implementation

    def decode_bytes(self, bytes: bytearray) -> int:
        pass  # Replace with actual implementation to decode the byte array

class DebugRegisterSource:
    DEBUG_REGSRC_DEBUGGEE = "DEBUG REG SRC DEBGEE"
