import tkinter as tk
from tkinter import ttk
from typing import List

class ProcessorStateDialog:
    def __init__(self, program_context):
        self.program_context = program_context
        self.register_list: List[Register] = []
        for register in program_context.get_context_registers():
            if not register.is_base_register():
                self.register_list.append(register)
        
        current_context = program_context.get_default_disassembly_context()
        self.add_ok_button()
        self.add_cancel_button()

    def add_ok_button(self):
        pass

    def add_cancel_button(self):
        pass

    def set_radix(self, radix: int) -> None:
        for field in self.fields:
            field.set_format(radix)

    def set_register_value(self, register_value: RegisterValue, register: Register, value: BigInteger) -> RegisterValue:
        new_value = RegisterValue(register, value)
        return register_value.combine_values(new_value)

    def ok_callback(self):
        new_value = RegisterValue(self.program_context.get_base_context_register())
        for i in range(len(self.fields)):
            if self.fields[i].get_value() is not None:
                new_value = self.set_register_value(new_value, self.register_list[i], self.fields[i].get_value())
        self.program_context.set_default_disassembly_context(new_value)
        self.close()

    def dispose(self):
        self.close()
