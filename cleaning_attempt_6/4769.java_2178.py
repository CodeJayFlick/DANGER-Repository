class EncryptedInformationCommand:
    def __init__(self):
        self.cryptoff = None
        self.cryptsize = None
        self.cryptid = None

    @classmethod
    def create_encrypted_information_command(cls, reader):
        command = cls()
        command.init_encrypted_information_command(reader)
        return command

    def init_encrypted_information_command(self, reader):
        if not hasattr(self, 'cryptoff'):
            self.cryptoff = reader.read_int()
        if not hasattr(self, 'cryptsize'):
            self.cryptsize = reader.read_int()
        if not hasattr(self, 'cryptid'):
            self.cryptid = reader.read_int()

    def get_crypt_id(self):
        return self.cryptid

    def get_crypt_offset(self):
        return self.cryptoff

    def get_crypt_size(self):
        return self.cryptsize

    def get_command_name(self):
        return "encryption_info_command"

    def markup(self, header, api, base_address, is_binary, parent_module, monitor, log):
        try:
            if is_binary:
                create_fragment(api, base_address, parent_module)
                address = base_address.get_new_address(get_start_index())
                api.create_data(address, to_data_type())
        except Exception as e:
            log.append_msg("Unable to create " + self.get_command_name())

    def to_data_type(self):
        struct = StructureDataType(self.get_command_name(), 0)
        struct.add(DWORD, "cmd", None)
        struct.add(DWORD, "cmdsize", None)
        struct.add(DWORD, "cryptoff", None)
        struct.add(DWORD, "cryptsize", None)
        struct.add(DWORD, "cryptid", None)
        struct.set_category_path(CategoryPath(MachConstants.DATA_TYPE_CATEGORY))
        return struct
