class TypeIDItem:
    def __init__(self, reader):
        self.descriptor_index = reader.read_int()

    @property
    def descriptor_index(self):
        return self.descriptor_index

    def to_data_type(self) -> dict:
        data_type = {"category_path": "/dex"}
        return data_type


class BinaryReader:
    def read_next_int(self) -> int:
        # implement your logic here for reading the next integer from a binary file
        pass


from abc import ABC, abstractmethod

class StructConverter(ABC):
    @abstractmethod
    def to_data_type(self) -> dict:
        pass
