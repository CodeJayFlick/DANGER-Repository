import os
from io import BytesIO
try:
    from typing import Any
except ImportError:
    pass  # Not necessary for this script

class PageHeaderTest:
    UNCOMPRESSED_SIZE = 123456
    COMPRESSED_SIZE = 100000
    NUM_OF_VALUES = 10000
    MAX_TIMESTAMPO = 523372036854775806L
    MIN_TIMESTAMPO = 423372036854775806L
    DATA_TYPE = 'INT64'
    PATH = "outputPageHeader.tsfile"

    def setUp(self):
        pass

    @classmethod
    def tearDown(cls):
        if os.path.exists(cls.PATH):
            try:
                os.remove(cls.PATH)
            except Exception as e:
                print(f"Error deleting file: {e}")

    def test_write_into_file(self):
        header = TestHelper.create_test_page_header()
        self._serialized(header)
        read_header = self._deserialized()
        if not Utils.is_page_header_equal(header, read_header):
            raise AssertionError("Page headers are not equal")
        self._serialized(read_header)

    @classmethod
    def _deserialized(cls):
        try:
            with open(cls.PATH, 'rb') as f:
                header = PageHeader.deserialize_from(f, cls.DATA_TYPE, True)
                return header
        except Exception as e:
            print(f"Error deserializing file: {e}")
        finally:
            if os.path.exists(cls.PATH):
                try:
                    os.remove(cls.PATH)
                except Exception as e:
                    print(f"Error deleting file: {e}")

    @classmethod
    def _serialized(cls, header):
        with open(cls.PATH, 'wb') as f:
            header.serialize_to(f)

if __name__ == "__main__":
    PageHeaderTest().test_write_into_file()
