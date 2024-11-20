Here is a translation of the Java code into equivalent Python:

```Python
class SubFrameworkCommand:
    def __init__(self):
        pass

    @staticmethod
    def create_sub_framework_command(reader):
        command = reader.get_factory().create(SubFrameworkCommand)
        command.init_sub_framework_command(reader)
        return command

    def init_sub_framework_command(self, reader):
        self.init_load_command(reader)
        self.umbrella = LoadCommandString.create_load_command_string(reader, self)

    @property
    def umbrella_framework_name(self):
        return self.umbrella

    def to_data_type(self):
        struct = StructureDataType(get_command_name(), 0)
        struct.add(DWORD, "cmd", None)
        struct.add(DWORD, "cmdsize", None)
        struct.add(self.umbrella.to_data_type(), "umbrella", None)
        struct.set_category_path(MachConstants.DATA_TYPE_CATEGORY)
        return struct

    @property
    def command_name(self):
        return "sub_framework_command"

    def markup(self, header, api, base_address, is_binary, parent_module, monitor, log):
        self.update_monitor(monitor)
        if is_binary:
            try:
                create_fragment(api, base_address, parent_module)
            except Exception as e:
                log.append_exception(e)

            address = base_address.get_new_address(get_start_index())
            try:
                api.create_data(address, self.to_data_type())
            except Exception as e:
                log.append_msg(f"Unable to create {self.command_name} - {e.message}")

            str_len = get_command_size() - self.umbrella.offset
            address_str = address.add(self.umbrella.offset)
            try:
                api.create_ascii_string(address_str, str_len)
            except Exception as e:
                log.append_msg(f"Unable to create load command string for {self.command_name} - {e.message}")

    def update_monitor(self, monitor):
        pass

    @staticmethod
    def get_start_index():
        return 0

class LoadCommandString:
    @staticmethod
    def create_load_command_string(reader, self):
        # implementation of this method is missing in the original code
        pass

class StructureDataType:
    def __init__(self, name, size):
        self.name = name
        self.size = size

    def add(self, data_type, field_name, default_value):
        pass

    @property
    def category_path(self):
        return None

class MachConstants:
    DATA_TYPE_CATEGORY = "Mach Constants"

def create_fragment(api, base_address, parent_module):
    # implementation of this method is missing in the original code
    pass

def get_command_name():
    return "sub_framework_command"

def get_start_index():
    return 0

# Usage example:

reader = Reader()  # Replace with your reader object
command = SubFrameworkCommand.create_sub_framework_command(reader)
print(command.umbrella_framework_name)