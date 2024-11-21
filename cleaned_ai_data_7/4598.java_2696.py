class AoutHeaderFactory:
    @staticmethod
    def create_aout_header(reader: 'BinaryReader', header: 'CoffFileHeader') -> 'AoutHeader':
        if header.optional_header_size == 0:
            return None

        match header.magic:
            case CoffMachineType.IMAGE_FILE_MACHINE_R3000:
                return AoutHeaderMIPS(reader)
            case _:
                return AoutHeader(reader)

class BinaryReader:
    pass

class CoffFileHeader:
    def __init__(self):
        self.optional_header_size = 0
        self.magic = None

class AoutHeader:
    def __init__(self, reader: 'BinaryReader'):
        pass

class AoutHeaderMIPS(AoutHeader):
    def __init__(self, reader: 'BinaryReader'):
        super().__init__(reader)
