from tkinter import *
import math

class RegisterWrapper:
    def __init__(self, register):
        self.register = register
        self.display_name = f"{register.name} ({register.bit_length})"

    def get_aliases(self):
        return ", ".join(register.aliases)

    def __str__(self):
        return self.display_name

    def __lt__(self, other):
        return self.register.name.lower() < other.register.name.lower()

class SetRegisterValueDialog:
    def __init__(self, program, registers, register, addr_set, use_value_field=False):
        super().__init__()
        self.program = program
        self.addr_set = addr_set
        self.use_value_field = use_value_field

        self.panel = Panel(self)
        self.register_combobox = Combobox(self)
        self.value_field = FixedBitSizeValueField(32)

        if not use_value_field:
            self.ok_button = Button(self, text="Set Register Values", command=self.ok_callback)
        else:
            self.ok_button = Button(self, text="Clear Register Values", command=self.ok_callback)

    def build_work_panel(self):
        for i in range(len(registers)):
            wrapper = RegisterWrapper(registers[i])
            self.register_combobox.append(wrapper.display_name)

        if not use_value_field:
            label = Label(self.panel, text="Register:")
            self.panel.add(label)
            self.panel.add(self.register_combobox)
        else:
            label1 = Label(self.panel, text="Value:")
            value_label = Label(self.panel, textvariable=self.value_field.get_text())
            self.panel.add(label1)
            self.panel.add(value_field)

    def update_ok_enablement(self):
        if not use_value_field and register_combobox.get():
            ok_button.config(state=NORMAL)
        else:
            ok_button.config(state=DISABLED)

    def set_selected_register(self, register):
        for i in range(len(registers)):
            wrapper = RegisterWrapper(registers[i])
            if wrapper.register == register:
                self.register_combobox.set(wrapper.display_name)
                return
        update_value()

    def update_value(self):
        if addr_set.get_num_addresses() == 1:
            address = addr_set.get_min_address()
            value = program.get_program_context().get_register_value(do_get_selected_register(), address)
            if value is not None:
                unsigned_value = value.get_unsigned_value()
                if unsigned_value is not None:
                    self.value_field.set(unsigned_value)
                    return
        self.value_field.set(None)

    def wrap_registers(self, registers):
        register_wrappers = [RegisterWrapper(register) for register in registers]
        register_wrappers.sort(key=lambda x: x.register.name.lower())
        return register_wrappers

    def set_address_ranges(self, addr_set):
        range_data = []
        for address_range in addr_set:
            start = address_range.get_min_address()
            end = address_range.get_max_address()
            if start == end:
                range_data.append(start.to_string())
            else:
                range_data.append(f"{start} - {end}")
        self.address_list.set_listdata(range_data)

    def ok_callback(self):
        register_value = self.value_field.get()
        selected_register = do_get_selected_register()
        close()

    def get_register_value(self):
        return register_value

    def do_get_selected_register(self):
        wrapper = RegisterWrapper(registers[self.register_combobox.current()])
        if wrapper is not None:
            return wrapper.register
        else:
            return None


class FixedBitSizeValueField(StringVar):
    def __init__(self, bit_size, unsigned=True, readonly=False):
        super().__init__()
        self.bit_size = bit_size
        self(unsigned=unsigned)
        self.readonly = readonly

    def set(self, value):
        if isinstance(value, str) and value.lower() == "none":
            return None
        elif not isinstance(value, int):
            raise ValueError("Invalid value")
        else:
            super().set(f"{value:b}".zfill(self.bit_size))


class Combobox(OptionMenu):
    def __init__(self, master, *args):
        OptionMenu.__init__(self, master, StringVar(), *args)


class Panel(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
