class UnsupportedLoadCommand:
    def __init__(self):
        pass

    @staticmethod
    def create_unsupported_load_command(reader, type) -> 'UnsupportedLoadCommand':
        command = reader.get_factory().create(UnsupportedLoadCommand)
        command.init_unsupported_load_command(reader, type)
        return command

    def init_unsupported_load_command(self, reader, type):
        self.init_load_command(reader)
        self.type = type

    @property
    def get_command_name(self) -> str:
        return f"Unsupported Load Command Type 0x{self.type:x}"

    def markup(self, header: 'MachHeader', api: 'FlatProgramAPI', base_address: int, is_binary: bool,
               parent_module: 'ProgramModule', monitor: 'TaskMonitor', log: 'MessageLog'):
        self.update_monitor(monitor)
        if is_binary:
            try:
                self.create_fragment(api, base_address, parent_module)
                address = base_address + self.get_start_index()
                api.create_data(address, self.to_data_type())
            except Exception as e:
                log.append_msg(f"Unable to create {self.get_command_name} - {e}")

    @property
    def to_data_type(self) -> 'DataType':
        struct = DataType(0)
        struct.add(DWORD, "cmd", None)
        struct.add(DWORD, "cmdsize", None)
        struct.set_category_path(CategoryPath(MachConstants.DATA_TYPE_CATEGORY))
        return struct

class MachHeader:
    pass

class FlatProgramAPI:
    def create_data(self, address: int, data_type: 'DataType'):
        pass

class ProgramModule:
    pass

class TaskMonitor:
    def update_monitor(self):
        pass

class MessageLog:
    def append_msg(self, message: str):
        pass
