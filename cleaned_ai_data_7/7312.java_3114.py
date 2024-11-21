import io
from typing import List

class Apple8900FileSystem:
    def __init__(self, file_system_name: str, provider):
        self.data_file = None
        super().__init__(file_system_name, provider)

    def close(self) -> None:
        self.data_file = None

    def get_byte_provider(self, file: 'GFile', monitor=None) -> io.BytesIO:
        if file and file == self.data_file:
            return fs_service.get_derived_bytes_io(provider.fsrl(), file.fsrl(), file.name, -1,
                                                     lambda: Apple8900Decryptor().decrypt(None, None, provider, monitor).decrypted_stream)
        return None

    def get_listing(self, directory) -> List['GFile']:
        tmp = []
        if not directory or directory == self.root:
            tmp.append(self.data_file)
        return tmp

    def is_valid(self, monitor=None) -> bool:
        magic = provider.read_bytes(0, Apple8900Constants.MAGIC_LENGTH)
        return bytes(magic) == Apple8900Constants.MAGIC_BYTES

    def open(self):
        header = Apple8900Header(provider)

        if not header.get_magic().equals(Apple8900Constants.MAGIC):
            raise io.IOException("Unable to decrypt file: invalid Apple 8900 file!")

        self.data_file = GFileImpl.from_filename(self, self.root, "DATA", False, header.size_of_data(), None)
