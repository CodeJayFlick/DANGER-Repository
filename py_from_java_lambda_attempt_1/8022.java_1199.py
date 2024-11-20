Here is the translation of the given Java code into Python:

```Python
class PdbDebugInfoParser:
    DBIHDR700_SIG = 0xffffffff
    DBI41_ID = 930803
    DBI50_ID = 19960307
    DBI60_ID = 19970606
    DBI70_ID = 19990903
    DBI110_ID = 20091201

    def __init__(self):
        self.debug_reader = None

    # API
    def parse(self, pdb) -> 'PdbDebugInfo':
        try:
            stream_number = self.get_stream_number()
            reader = pdb.get_reader_for_stream_number(stream_number, 0, 8)
            if reader.limit == 0:
                return None

            debug_reader = reader
            print(f"DebugInfoParser data on stream {stream_number}:")
            print(debug_reader.dump())

            header_signature = int.from_bytes(reader.read(4), 'little')
            version_number = int.from_bytes(reader.read(4), 'little')

            if header_signature == self.DBIHDR700_SIG:
                match version_number:
                    case self.DB41_ID | self.DB50_ID | self.DB60_ID | self.DB70_ID | self.DB110_ID:
                        debug_info = PdbNewDebugInfo(pdb, stream_number)
                        break
                    case _:
                        raise PdbException("Unknown DBI Version")
            else:
                debug_info = PdbOldDebugInfo(pdb, stream_number)

        except CancelledError as e:
            raise AssertException() from e

        return debug_info

    def debug_dump(self):
        return f"DebugInfoParser data on stream {self.get_stream_number()}:\n{self.debug_reader.dump}\n"

    # Internal Data Methods
    def get_stream_number(self) -> int:
        return self.DATABASE_INTERFACE_STREAM_NUMBER


class PdbByteReader:
    def __init__(self, limit):
        self.limit = limit

    def read(self, size: int):
        if self.limit < size:
            raise ValueError("Not enough bytes available")
        result = self.limit - size
        self.limit -= size
        return bytearray(size)

    def dump(self) -> str:
        # implement this method to get the actual data as a string
        pass


class PdbDebugInfo:
    pass


class AbstractPdb:
    def __init__(self):
        pass

    def get_reader_for_stream_number(self, stream_number: int, offset: int, size: int) -> 'PdbByteReader':
        # implement this method to return a reader for the given stream number
        pass


class PdbNewDebugInfo(PdbDebugInfo):
    def __init__(self, pdb, stream_number):
        self.pdb = pdb
        self.stream_number = stream_number


class PdbOldDebugInfo(PdbDebugInfo):
    def __init__(self, pdb, stream_number):
        self.pdb = pdb
        self.stream_number = stream_number


class PdbException(Exception):
    pass


class AssertException(Exception):
    pass
```

Please note that this translation is not a direct conversion from Java to Python. The provided code has been modified to fit the syntax and structure of Python, but it may still require some adjustments based on your specific requirements.

Also, please be aware that there are several classes (`PdbByteReader`, `AbstractPdb`, `PdbDebugInfo`, etc.) in this translation which do not have a direct equivalent in Java. These were added to accommodate the differences between Python and Java syntax.