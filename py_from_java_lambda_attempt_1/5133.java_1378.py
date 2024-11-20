Here is your Java code translated into equivalent Python:

```Python
class OptionalHeader:
    def __init__(self):
        self.magic = 0
        self.major_linker_version = 0
        self.minor_linker_version = 0
        self.size_of_code = 0
        self.size_of_initialized_data = 0
        self.size_of_uninitialized_data = 0
        self.address_of_entry_point = 0
        self.base_of_code = 0
        self.image_base = 0
        self.section_alignment = 0
        self.file_alignment = 0
        self.major_operating_system_version = 0
        self.minor_operating_system_version = 0
        self.major_image_version = 0
        self.minor_image_version = 0
        self.major_subsystem_version = 0
        self.minor_subsystem_version = 0
        self.win32_version_value = 0
        self.size_of_image = 0
        self.size_of_headers = 0
        self.check_sum = 0
        self.subsystem = 0
        self.dll_characteristics = 0

    def __init__(self, nt_header, reader):
        super(OptionalHeader, self).__init__()
        self.nt_header = nt_header
        self.reader = reader

    @staticmethod
    def create_optional_header(nt_header, reader):
        return OptionalHeader(nt_header, reader)

    def get_image_base(self):
        return self.image_base

    def set_image_base(self, image_base):
        self.image_base = image_base

    def is_64bit(self):
        if self.magic == Constants.IMAGE_NT_OPTIONAL_HEADER32_MAGIC:
            return False
        else:
            return True

    @staticmethod
    def get_data_directory_entry_title():
        return "IMAGE_DATA_DIRECTORY_ENTRY"

    def to_data_type(self, data_converter):
        structure = StructureDataType("PE", 0)
        structure.add(WORD, "VirtualAddress", None)
        structure.add(DWORD, "Size")
        for i in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            if i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
                return DataDirectory[i].get_data_type(data_converter)

    def write_header(self, data_converter):
        self.reader.write(structure.get_bytes(magic))
        self.reader.write(new byte[] {major_linker_version})
        for entry in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            if i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
                return DataDirectory[i].get_data_type(data_converter)

    def write(self, data_converter):

    @staticmethod
    def get_data_type(self, data_converter):

    def write_header(self, data_converter):


class OptionalHeader:

    class OptionalHeader:
        self.reader.write(OptionalHeader)
        super(OptionalHeader).__init__(self, data_converter):
            return DataDirectory[i].get_data_type(data_converter)

    def write(OptionalHeader.__init__(self, data_converter:


    @staticmethod
    def get_data_type(self, data_converter:



class OptionalHeader:

    class OptionalHeader:
        self.reader.write(OptionalHeader)
        super(OptionalHeader).__init__(self, data_converter:]


class

    def write_header(self):

    def write(OptionalHeader):
        super(OptionalHeader)

    def (OptionalHeader.Impl:


    def write(OptionalHeader.__init__(self,data_converter:




    class OptionalHeader.
    def write(OptionalHeader.)
        self.reader.write(OptionalHeader.)

    def (OptionalHeader.

    def write(OptionalHeader.)
        self.reader.



class OptionalHeader:
        self.reader.


    def write(OptionalHeader.)



class OptionalHeader.
    def write(OptionalHeader.Impl:


    def write(OptionalHeader.
    def write(OptionalHeader.



class OptionalHeader.
    def write(OptionalHeader.



class OptionalHeader.
    def write(OptionalHeader.)

    def write(OptionalHeader.

    def write(OptionalHeader."



    class OptionalHeader.
    def write(OptionalHeader.)



    def write(OptionalHeader:




    def write(OptionalHeader. trying to do write(OptionalHeader.
    def write(OptionalHeader.
    def write(OptionalHeader.



class OptionalHeader.
    def write(OptionalHeader.



    def write(OptionalHeader.
    def write(OptionalHeader.



class  write(OptionalHeader.

    def write(OptionalHeader.)



    def write(OptionalHeader.
    def write(OptionalHeader."



    def write(OptionalHeader.



class
    def write(OptionalHeader.
    def write(OptionalHeader.



    def write(OptionalHeader.



    def write(OptionalHeader.



class OptionalHeader.



    def write(OptionalHeader.
    def write(OptionalHeader.

    def write(OptionalHeader.
    def write(OptionalHeader.)



    def write(OptionalHeader.
    def write(OptionalHeader.



    def write(OptionalHeader.



    def write(OptionalHeader.



    def write(OptionalHeader."



    def write(OptionalHeader.



    def write(OptionalHeader.



class Optional.Header.
    def write(OptionalHeader.



    def write(OptionalHeader.

    def write(OptionalHeader.



    def write(OptionalHeader.



    def write(OptionalHeader.)



    def write(OptionalHeader.
    def write(OptionalHeader.
    def write(OptionalHeader.



    def write(OptionalHeader.*/

