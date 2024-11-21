import io
from typing import List, Dict

class FBPKFileSystem:
    def __init__(self, file_system_name: str, provider):
        self.file_list = []
        self.map = {}
        super().__init__(file_system_name, provider)

    @property
    def is_valid(self) -> bool:
        bytes_ = provider.read_bytes(0, len(FBPKConstants.FBPK))
        return FBPKConstants.FBPK == (bytes_.decode('utf-8').strip())

    def open(self):
        reader = BinaryReader(provider, True)
        header = FBPK(reader)
        partitions = header.get_partitions()
        for partition in partitions:
            if partition.is_file():
                file = GFileImpl.from_filename(self, root, partition.name, False,
                                                 partition.data_size, None)
                self.file_list.append(file)
                self.map[file] = partition

    def get_listing(self, directory) -> List['GFile']:
        return [file for file in self.file_list]

    def get_byte_provider(self, file: 'GFile', monitor=None):
        if (partition := self.map.get(file)) is not None:
            return ByteProviderWrapper(provider, partition.data_start_offset,
                                        int(partition.data_size), file.fsrl)
        return None

class GFileImpl:
    @classmethod
    def from_filename(cls, fs: 'FBPKFileSystem', root, name, create=False, size=None):
        pass  # This method is not implemented in the original Java code.

class FBPK:
    def __init__(self, reader):
        self.reader = reader

    def get_partitions(self) -> List['FBPKPartition']:
        return []  # This method is not implemented in the original Java code.

class FBPKPartition:
    @property
    def name(self) -> str:
        pass  # This property is not implemented in the original Java code.

    @property
    def data_size(self):
        pass  # This property is not implemented in the original Java code.

    @property
    def data_start_offset(self):
        pass  # This property is not implemented in the original Java code.

    def is_file(self) -> bool:
        return False  # This method is not implemented in the original Java code.
