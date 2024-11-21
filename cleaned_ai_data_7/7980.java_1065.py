class AbstractTypeProgramInterface:
    def __init__(self, pdb: 'AbstractPdb', record_category: 'RecordCategory', stream_number: int):
        self.pdb = pdb
        self.record_category = record_category
        self.stream_number = stream_number

    @staticmethod
    def get_version_number_size() -> int:
        return 4

    @classmethod
    def deserialize_version_number(cls, reader) -> int:
        return reader.read_int()

    def __init__(self):
        pass

    def set_record(self, record_number: int, type_: 'AbstractMsType') -> bool:
        if record_number < self.type_index_min:
            return False
        for i in range(len(self.type_list), record_number - self.type_index_min + 1):
            self.type_list.append(type_)
        return True

    def add_record(self, type_: 'AbstractMsType') -> int:
        new_record_num = len(self.type_list) + self.type_index_min
        self.type_list.append(type_)
        return new_record_num

    @abstractmethod
    def deserialize_header(self, reader: 'PdbByteReader'):
        pass

    @abstractmethod
    def dump_header(self, writer):
        pass

class TypeProgramInterfaceHash:
    def __init__(self):
        pass

    def deserialize_hash_streams(self, monitor) -> None:
        if self.hash_stream_number == 0xffff:
            return
        reader = self.pdb.get_reader_for_stream_number(self.hash_stream_number)
        # do something with the reader...

class TiOff:
    def __init__(self, type_index: int):
        self.type_index = type_index

    @abstractmethod
    def parse(self, reader) -> None:
        pass

    @abstractmethod
    def get_size(self) -> int:
        pass


# Usage example:

pdb = AbstractPdb()
record_category = RecordCategory()
stream_number = 0x1234

tpi = AbstractTypeProgramInterface(pdb, record_category, stream_number)

tpi.deserialize_header(reader)
