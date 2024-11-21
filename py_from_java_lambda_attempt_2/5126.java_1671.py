Here is a translation of the Java code into equivalent Python:

```Python
class LoadConfigDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"

    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    @staticmethod
    def create_load_config_data_directory(nt_header, reader) -> 'LoadConfigDataDirectory':
        load_config_data_directory = LoadConfigDataDirectory()
        load_config_data_directory.init_load_config_data_directory(nt_header, reader)
        return load_config_data_directory

    def init_load_config_data_directory(self, nt_header: object, reader: object):
        self.process_data_directory(nt_header, reader)

    @property
    def load_config_directory(self) -> 'LoadConfigDirectory':
        return self.lcd

    def get_directory_name(self) -> str:
        return self.NAME

    def markup(self, program: object, is_binary: bool, monitor: object, log: object,
               nt_header: object):
        if not program.memory.contains(PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)):
            return
        create_directory_bookmark(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address))
        
        PeUtils.create_data(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address), self.lcd.to_data_type(), log)

        self.markup_se_handler(program, is_binary, monitor, log, nt_header)
        ControlFlowGuard.markup(self.lcd, program, log, nt_header)

    def markup_se_handler(self, program: object, is_binary: bool, monitor: object,
                          log: object, nt_header: object):
        exception_count = self.lcd.get_se_handler_count()
        if exception_count > NTHeader.MAX_SANE_COUNT:
            return

        address = program.address_factory.default_address_space.get_address(
            PeUtils.va(self.lcd.get_se_handler_table() - nt_header.optional_header.image_base(), is_binary))
        
        set_plate_comment(program, address,
                           f"SEHandlerTable (0x{exception_count:x} entries)")

        for i in range(int(exception_count)):
            if monitor.is_cancelled():
                return
            data_type = NTHeader.IMG_64BIT if nt_header.optional_header.image_base() >= 2**32 else ImageBaseOffset32DataType()
            
            PeUtils.create_data(program, address, data_type, log)
            
            address += data_type.length

    def parse(self) -> bool:
        pointer = self.get_pointer()
        if pointer < 0:
            return False
        
        self.lcd = LoadConfigDirectory.create_load_config_directory(reader=reader, ptr=pointer, nt_header=nt_header.optional_header)

        return True

    @property
    def to_data_type(self):
        return self.lcd.to_data_type()

class PeUtils:
    @staticmethod
    def get_markup_address(program: object, is_binary: bool, nt_header: object, virtual_address: int) -> Address:
        pass  # implement this method

    @staticmethod
    def create_directory_bookmark(program: object, address: Address):
        pass  # implement this method

    @staticmethod
    def va(address: int, is_binary: bool) -> int:
        if is_binary:
            return address
        else:
            return address & 0xFFFFFFFF

class ControlFlowGuard:
    @staticmethod
    def markup(lcd: LoadConfigDirectory, program: object, log: object, nt_header: object):
        pass  # implement this method