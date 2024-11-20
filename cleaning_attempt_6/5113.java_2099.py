class ExceptionDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_EXCEPTION"

    def __init__(self):
        pass

    @staticmethod
    def create_exception_data_directory(nt_header, reader) -> 'ExceptionDataDirectory':
        exception_data_directory = reader.get_factory().create(ExceptionDataDirectory)
        exception_data_directory.init_exception_data_directory(nt_header, reader)
        return exception_data_directory

    def init_exception_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

    def get_directory_name(self) -> str:
        return self.NAME

    def parse(self) -> bool:
        ptr = self.get_pointer()
        if ptr < 0:
            return False
        return True

    def markup(self, program: 'Program', is_binary: bool, monitor: 'TaskMonitor', log: 'MessageLog',
               nt_header: 'NTHeader') -> None:
        monitor.set_message(f"{program.name}: exceptions...")
        addr = PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)
        if not program.memory.contains(addr):
            return
        self.create_directory_bookmark(program, addr)

    def to_data_type(self) -> 'DataType':
        struct = DataType(StructureType(), name=self.NAME, size=self.size)
        struct.set_category_path(CategoryPath("/PE"))
        return struct

class Program:
    pass

class TaskMonitor:
    def set_message(self, message: str):
        pass

class MessageLog:
    pass

class NTHeader:
    pass

class PeUtils:
    @staticmethod
    def get_markup_address(program: 'Program', is_binary: bool, nt_header: 'NTHeader', virtual_address) -> Address:
        pass

class ProgramMemory:
    def contains(self, addr):
        return True  # Assuming the memory always contains an address.

class CategoryPath:
    pass

class StructureType:
    pass
