class ObsoleteCommand:
    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    def init_obsolete_command(self, reader):
        self.init_load_command(reader)
        raise Exception("ObsoleteException")

    def to_data_type(self):
        struct = {"cmd": "DWORD", "cmdsize": "DWORD", "obsolete": f"BYTE[{self.get_command_size() - 8}]"}
        return struct

    def get_byte_array(self):
        return [f"BYTE"] * (self.get_command_size() - 8)

    def markup(self, header, api, base_address, is_binary, parent_module, monitor, log):
        self.update_monitor(monitor)
        try:
            if is_binary:
                self.create_fragment(api, base_address, parent_module)
                addr = base_address + self.get_start_index()
                api.create_data(addr, self.to_data_type())
        except Exception as e:
            log.append(f"Unable to create {self.get_command_name()} - {e}")

class LoadCommand:
    def __init__(self):
        pass

    def init_load_command(self, reader):
        # implementation of this method is missing in the provided Java code
        pass

# This class does not have a direct equivalent in Python. It seems to be used for creating fragments.
