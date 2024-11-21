class OatHeader:
    def __init__(self):
        self.magic = None
        self.version = None

    def parse(self, reader, additional_data=None) -> None:
        pass  # abstract method in Python

    @property
    def magic(self):
        return self._magic

    @magic.setter
    def magic(self, value):
        self._magic = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    def get_magic(self) -> str:
        return self.magic

    def get_version(self) -> str:
        return self.version

    def get_dex_file_count(self) -> int:
        pass  # abstract method in Python

    def get_key_value_store_size(self) -> int:
        pass  # abstract method in Python

    def get_oat_dex_file_list(self) -> list:
        pass  # abstract method in Python

    def get_instruction_set(self) -> str:  # assuming OatInstructionSet is an enum
        return "ARM" or "X86"

    def get_executable_offset(self) -> int:
        pass  # abstract method in Python

    def get_checksum(self) -> int:
        pass  # abstract method in Python


class BinaryReader:
    def read_next_byte_array(self, length):
        pass  # abstract method in Python

    def read_next_ascii_string(self, length):
        pass  # abstract method in Python
