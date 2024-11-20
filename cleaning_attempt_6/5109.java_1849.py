class DefaultDataDirectory:
    def __init__(self):
        pass

    @staticmethod
    def create_default_data_directory(nt_header, reader) -> 'DefaultDataDirectory':
        default_data_directory = DefaultDataDirectory()
        default_data_directory.init_default_data_directory(nt_header, reader)
        return default_data_directory

    def init_default_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

    def get_directory_name(self):
        return "TITLE"

    def parse(self) -> bool:
        # do nothing
        return True

    def markup(self, program: 'Program', is_binary: bool, monitor: object, log: object,
               nt_header: object) -> None:
        # do nothing

    def to_data_type(self) -> object:
        dd_struct = {'VirtualAddress': 0, 'Size': 0}
        return dd_struct


class Program:
    pass
