Here is the translation of the Java code into Python:

```Python
import io
from typing import List

class MsfReaderUnitTest:
    STREAM_OUTPUT_MAX = 0x80

    IDENTIFICATION_200 = "Microsoft C/CC++ program database 2.00\r\n\u001aJG".encode()
    padding200 = b'\x00\x00'

    IDENTIFICATION_700 = "Microsoft C/C++ MSF 7.00\r\n\u001aDS".encode()
    padding700 = b'\x00\x00\x00'

    def __init__(self):
        pass

    @classmethod
    def setUp(cls) -> None:
        cls.tDir = create_temp_directory("msfreader")
        cls.testFile200 = File(os.path.join(cls.tDir, "msfreader200.pdb"))
        cls.testFileName200 = cls.testFile200.get_absolute_path()
        buffer200 = create_stream_file_200().encode()
        stream200 = open(cls.testFile200, 'wb')
        stream200.write(buffer200)
        stream200.close()

        cls.testFile700 = File(os.path.join(cls.tDir, "msfreader700.pdb"))
        cls.testFileName700 = cls.testFile700.get_absolute_path()
        buffer700 = create_stream_file_700().encode()
        stream700 = open(cls.testFile700, 'wb')
        stream700.write(buffer700)
        stream700.close()

    @classmethod
    def tearDown(cls) -> None:
        if cls.testFileName200 is not None:
            print(f"MSF test file used: {cls.testFileName200}")
        if cls.testFileName700 is not None:
            print(f"MSF test file used: {cls.testFileName700}")

    @staticmethod
    def dump_stream(stream_file, stream_number, max_out) -> str:
        stream = stream_file.get_stream(stream_number)
        builder = StringBuilder()
        builder.append(f"Stream: {stream_number}\n")
        builder.append(stream.dump(max_out))
        return builder.toString()

    @classmethod
    def test_stream_file_200_header(cls):
        try:
            stream_file = MsfParser.parse(cls.testFileName200, PdbReaderOptions(), TaskMonitor.DUMMY)
            num_streams = stream_file.get_num_streams()
            for i in range(num_streams):
                print(stream_file.get_stream(i).dump(MsfReaderUnitTest.STREAM_OUTPUT_MAX))
        except Exception as e:
            assert isinstance(e.__class__, FileNotFoundError)

    @classmethod
    def test_stream_file_700_header(cls):
        try:
            stream_file = MsfParser.parse(cls.testFileName700, PdbReaderOptions(), TaskMonitor.DUMMY)
            num_streams = stream_file.get_num_streams()
            for i in range(num_streams):
                print(stream_file.get_stream(i).dump(MsfReaderUnitTest.STREAM_OUTPUT_MAX))
        except Exception as e:
            assert isinstance(e.__class__, FileNotFoundError)

    @classmethod
    def create_stream_file_200(cls) -> bytes:
        msf = MultiStreamFile(MsfVer.V200, 0x1000)
        stream = Stream(msf)
        data_stream_buffer = create_data_for_stream(0x1000).encode()
        stream.put_data(data_stream_buffer.encode())
        return msf.serialize().encode()

    @classmethod
    def create_stream_file_700(cls) -> bytes:
        msf = MultiStreamFile(MsfVer.V700, 0x1000)
        stream = Stream(msf)
        data_stream_buffer = create_data_for_stream(0x1000).encode()
        stream.put_data(data_stream_buffer.encode())
        return msf.serialize().encode()

    @classmethod
    def create_data_for_stream(cls, page_size: int) -> bytes:
        writer = PdbByteWriter()
        for _ in range(16):
            writer.put_unsigned_byte(0x55)
            writer.put_unsigned_byte(0xaa)
        for _ in range(16):
            writer.put_unsigned_short(0x1111)
            writer.put_unsigned_short(0xeeee)
        return writer.get().encode()

class MsfHeader:
    def __init__(self, msf: MultiStreamFile):
        self.msf = msf
        self.serialization_page_list = []

    def init(self) -> None:
        # By definition, header gets page 0.
        self.msf.fpm.reserve_page(0)
        self.serialization_page_list.append(0)

    def serialize(self, num_pages: int, fpm_pn: int, data_length: bytes) -> bytes:
        if self.msf.ver == MsfVer.V200:
            return create_stream_file_200_header(num_pages, fpm_pn, data_length).encode()
        else:
            return create_stream_file_700_header(num_pages, fpm_pn, data_length).encode()

class FreePageMap:
    def __init__(self, msf: MultiStreamFile):
        self.msf = msf
        self.serialization_page_list = []
        # num_used_pages not used, but would be if we allowed it fpm to grow or allowed modification
        #  model, in which case we would need to search the list first before adding to the list. Having the value could short-cut the need for searching.
        #self.num_used_pages = 0

    def init(self) -> None:
        # Taking page 1 for FreePageMap.
        self.reserve_page(1)
        self.serialization_page_list.append(1)

    def reserve_page(self, page_number: int) -> None:
        if not self[page_number]:
            fail("Page already free... terminating")
        self[page_number] = False

class Stream:
    def __init__(self, msf: MultiStreamFile):
        self.msf = msf
        self.stream_num = msf.st.add_stream(self)
        self.data = b''

    def serialize(self) -> bytes:
        return self.data.encode()

    def put_data(self, data_in: bytes) -> None:
        self.data = data_in

class DirectoryStream(Stream):
    pass

class MultiStreamFile:
    def __init__(self, ver: MsfVer, page_size: int):
        self.ver = ver
        self.page_size = page_size
        self.header = MsfHeader(self)
        self.fpm = FreePageMap(self)
        self.st = StreamTable(self)

    def serialize(self) -> bytes:
        output_buffer = bytearray(self.page_size * 0x20)
        for i in range(len(self.st.stream_numbers)):
            stream = self.st.get_stream(i)
            stream.serialize()
        return output_buffer

class MsfVer:
    V200 = 'V200'
    V700 = 'V700'

def create_temp_directory(directory_name: str) -> str:
    # Implement your own method to create a temporary directory
    pass

if __name__ == "__main__":
    test_file_200_header()
```

Please note that the above Python code is not exactly equivalent to the Java code. It's more of an approximation, as some parts are difficult or impossible to translate directly (e.g., static methods and classes).