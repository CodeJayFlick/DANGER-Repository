class FixedVirtualMemoryFileCommand:
    def __init__(self):
        pass

    @classmethod
    def create_fixed_virtual_memory_file_command(cls, reader):
        command = cls()
        command.init_fixed_virtual_memory_file_command(reader)
        return command

    def init_fixed_virtual_memory_file_command(self, reader):
        self.init_load_command(reader)

    def get_pathname(self):
        return str(self.name)

    def get_header_address(self):
        return self.header_addr

    @classmethod
    def to_data_type(cls):
        struct = {"cmd": 0, "cmdsize": 0, "name": None, "header_addr": 0}
        for key in struct:
            if isinstance(struct[key], str) or isinstance(struct[key], int):
                pass
            else:
                struct[key] = str(struct[key])
        return struct

    @classmethod
    def get_command_name(cls):
        return "fvmfile_command"

    def markup(self, header, api, base_address, is_binary, parent_module, monitor, log):
        self.update_monitor(monitor)
        if is_binary:
            try:
                create_fragment(api, base_address, parent_module)
            except Exception as e:
                log.append_exception(e)

            addr = base_address.get_new_address(self.get_start_index())
            try:
                api.create_data(addr, cls.to_data_type())
            except Exception as e:
                log.append_msg("Unable to create " + self.get_command_name() + " - " + str(e))

            try:
                str_len = self.get_command_size() - self.name.get_offset()
                str_addr = addr.add(self.name.get_offset())
                api.create_ascii_string(str_addr, str_len)
            except Exception as e:
                log.append_msg("Unable to create load command string for " + self.get_command_name() + " - " + str(e))

    def get_start_index(self):
        pass

def init_load_command(reader):
    # implementation
    pass

def update_monitor(monitor):
    # implementation
    pass

def create_fragment(api, base_address, parent_module):
    # implementation
    pass
