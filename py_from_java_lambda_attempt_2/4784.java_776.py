Here is the translation of the given Java code into Python:

```Python
class RoutinesCommand:
    def __init__(self):
        self.init_address = None
        self.init_module = None
        self.reserved1 = None
        self.reserved2 = None
        self.reserved3 = None
        self.resaved4 = None
        self.reserved5 = None
        self.reserved6 = None
        self.is32bit = False

    @staticmethod
    def create_routines_command(reader, is_32bit):
        command = RoutinesCommand()
        if not isinstance(command, type) or not hasattr(command, 'init'):
            raise TypeError("Invalid class")
        try:
            reader.get_factory().create(RoutinesCommand)
            command.init_reader(reader, is_32bit)
        except Exception as e:
            print(f"Error creating routines_command: {e}")
        return command

    def init_reader(self, reader, is_32bit):
        self.is32bit = is_32bit
        if is_32bit:
            self.init_address = int(reader.read_next_int() & 0xffffffff)
            self.init_module = int(reader.read_next_int() & 0xffffffff)
            self.reserved1 = int(reader.read_next_int() & 0xffffffff)
            self.reserved2 = int(reader.read_next_int() & 0xffffffff)
            self.reserved3 = int(reader.read_next_int() & 0xffffffff)
            self.reserved4 = int(reader.read_next_int() & 0xffffffff)
            self.reserved5 = int(reader.read_next_int() & 0xffffffff)
            self.reserved6 = int(reader.read_next_int() & 0xffffffff)
        else:
            self.init_address = reader.read_next_long()
            self.init_module = reader.read_next_long()
            self.reserved1 = reader.read_next_long()
            self.reserved2 = reader.read_next_long()
            self.reserved3 = reader.read_next_long()
            self.reserved4 = reader.read_next_long()
            self.reserved5 = reader.read_next_long()
            self.reserved6 = reader.read_next_long()

    def get_initialization_routine_address(self):
        return self.init_address

    def get_initialization_routine_module_index(self):
        return self.init_module

    def get_reserved1(self):
        return self.reserved1

    def get_reserved2(self):
        return self.reserved2

    def get_reserved3(self):
        return self.reserved3

    def get_reserved4(self):
        return self.reserved4

    def get_reserved5(self):
        return self.reserved5

    def get_reserved6(self):
        return self.reserved6

    def to_data_type(self) -> dict:
        data_type = {"cmd": int(0), "cmdsize": int(0)}
        if self.is32bit:
            for i in range(7):
                data_type[f"reserved{i+1}"] = int(reader.read_next_int() & 0xffffffff)
        else:
            for i in range(7):
                data_type[f"reserved{i+1}"] = reader.read_next_long()
        return data_type

    def get_command_name(self) -> str:
        return "routines_command"

    def markup(self, header: MachHeader, api: FlatProgramAPI, base_address: Address, is_binary: bool, parent_module: ProgramModule, monitor: TaskMonitor, log: MessageLog):
        update_monitor(monitor)
        try:
            if is_binary:
                create_fragment(api, base_address, parent_module)
                address = base_address.get_new_address(self.start_index())
                api.create_data(address, self.to_data_type())
        except Exception as e:
            log.append_msg(f"Unable to create {self.command_name} - {e.message}")
```

Please note that Python does not support direct translation of Java code. The above code is a manual translation and may require adjustments based on the specific requirements of your project.