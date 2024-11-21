import logging
from typing import List

class DictionaryDecoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.entry_index: List[bytes] = None
        self.value_decoder = IntRleDecoder()

    @property
    def has_next(self) -> bool:
        if not self.entry_index:
            self.init_map()
        try:
            return self.value_decoder.has_next
        except Exception as e:
            self.logger.error("tsfile-decoding DictionaryDecoder: error occurs when decoding", e)
        return False

    @property
    def read_binary(self, buffer) -> bytes:
        if not self.entry_index:
            self.init_map()
        code = self.value_decoder.read_int(buffer)
        return self.entry_index[code]

    def init_map(self):
        length = ReadWriteForEncodingUtils.read_var_int(buffer)
        self.entry_index: List[bytes] = [0]*length
        for i in range(length):
            binary_length = ReadWriteForEncodingUtils.read_var_int(buffer)
            buf = bytearray(binary_length)
            buffer.get(buf, 0, binary_length)
            self.entry_index[i] = bytes(buf)

    def reset(self) -> None:
        self.entry_index: List[bytes] = None
        self.value_decoder.reset()

class IntRleDecoder:
    @property
    def has_next(self):
        pass

    def read_int(self, buffer) -> int:
        pass

    def reset(self) -> None:
        pass


class ReadWriteForEncodingUtils:
    @staticmethod
    def read_var_int(buffer: bytes) -> int:
        pass


if __name__ == "__main__":
    decoder = DictionaryDecoder()
