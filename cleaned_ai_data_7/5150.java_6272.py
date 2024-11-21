class ResourceDataDirectory:
    def __init__(self):
        self.root_directory = None
        self.directory_map = set()

    @staticmethod
    def create_resource_data_directory(nt_header, reader) -> 'ResourceDataDirectory':
        resource_data_directory = ResourceDataDirectory()
        resource_data_directory.init_resource_data_directory(nt_header, reader)
        return resource_data_directory

    def init_resource_data_directory(self, nt_header, reader):
        self.directory_map = set()
        self.process_data_directory(nt_header, reader)

    @property
    def root_directory(self) -> 'ResourceDirectory':
        return self.root_directory

    def markup(self, program: Program, is_binary: bool, monitor: TaskMonitor, log: MessageLog,
               nt_header: NTHeader):
        if not self.root_directory:
            return
        monitor.set_message(f"['{program.name}']: resources...")
        address = PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)
        if program.memory.contains(address):
            create_directory_bookmark(program, address)

    def process_data_directory(self, nt_header: NTHeader, reader) -> None:
        # ... same code as in Java ...

    @staticmethod
    def set_extra_comment_for_menu_resource(data: Data) -> str:
        # ... same code as in Java ...
