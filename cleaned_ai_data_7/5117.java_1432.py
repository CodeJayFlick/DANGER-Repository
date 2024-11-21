class GlobalPointerDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"

    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    @classmethod
    def create_global_pointer_data_directory(cls, nt_header, reader):
        global_pointer_data_directory = cls(reader.get_factory().create(cls))
        global_pointer_data_directory.init_global_pointer_data_directory(nt_header, reader)
        return global_pointer_data_directory

    def init_global_pointer_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

    @property
    def directory_name(self):
        return self.NAME

    def markup(self, program, is_binary, monitor, log, nt_header):
        if not program.get_memory().contains(PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)):
            return
        self.create_directory_bookmark(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address))

    def parse(self):
        ptr = self.get_pointer()
        if ptr < 0:
            return False
        return True

    @property
    def to_data_type(self):
        struct = StructureDataType(f"{self.NAME}", 0)
        struct.add(ArrayDataType("BYTE", self.size, 1), "GLOBAL_PTR", None)
        struct.set_category_path(CategoryPath("/PE"))
        return struct


class PeUtils:
    @classmethod
    def get_markup_address(cls, program, is_binary, nt_header, virtual_address):
        # This method should be implemented based on the actual PE file format.
        pass

    @classmethod
    def process_data_directory(cls, nt_header, reader):
        # This method should be implemented based on the actual PE file format.
        pass


class StructureDataType:
    def __init__(self, name, size):
        self.name = name
        self.size = size

    def add(self, data_type, field_name, parent):
        # This method should be implemented based on the actual data type and its fields.
        pass

    def set_category_path(self, category_path):
        self.category_path = category_path


class CategoryPath:
    def __init__(self, path):
        self.path = path
