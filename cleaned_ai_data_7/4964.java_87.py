import io

class PdbInfo:
    @staticmethod
    def read(reader: 'BinaryReader', offset: int) -> 'PdbInfo':
        if PdbInfoCodeView.is_match(reader, offset):
            return PdbInfoCodeView.read(reader, offset)
        elif PdbInfoDotNet.is_match(reader, offset):
            return PdbInfoDotNet.read(reader, offset)
        else:
            return None

    def is_valid(self) -> bool:
        # TO DO: implement isValid method
        pass

    def serialize_to_options(self, options: 'Options') -> None:
        # TO DO: implement serializeToOptions method
        pass


class BinaryReader:
    @staticmethod
    def read(reader: 'io', offset: int) -> str:
        return reader.read(offset)


class Options:
    pass


# TO DO: define PdbInfoCodeView and PdbInfoDotNet classes
