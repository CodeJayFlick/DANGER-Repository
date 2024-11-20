class TLSDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_TLS"

    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    @classmethod
    def create_tls_data_directory(cls, nt_header, reader) -> 'TLSDataDirectory':
        tls_data_directory = cls()
        tls_data_directory.init_tls_data_directory(nt_header, reader)
        return tls_data_directory

    def init_tls_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

    @property
    def tls(self) -> 'TLSDirectory':
        return self._tls

    @tls.setter
    def tls(self, value: 'TLSDirectory'):
        self._tls = value

    def get_tls_directory(self) -> 'TLSDirectory':
        return self.tls

    def get_directory_name(self) -> str:
        return self.NAME

    def markup(self, program: 'Program', is_binary: bool, monitor: object, log: object,
               nt_header: object) -> None:
        if not program.memory.contains(PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)):
            return
        create_directory_bookmark(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address))
        PeUtils.create_data(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address), self.tls.to_data_type(), log)

    def parse(self) -> bool:
        ptr = self.get_pointer()
        if ptr < 0:
            return False
        try:
            self._tls = TLSDirectory.create_tls_directory(reader, ptr, nt_header.optional_header.is_64bit())
            return True
        except Exception as e:
            log.append_msg("TLS", f"Failed to parse TLS: {e}")
            return False

    def get_pointer(self) -> int:
        # implement this method
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    @property
    def virtual_address(self):
        # implement this property
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
