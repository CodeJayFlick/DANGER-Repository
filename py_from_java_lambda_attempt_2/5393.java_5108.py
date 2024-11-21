Here is the translation of the Java code into Python:

```Python
class IntelHexRecord:
    MAX_RECORD_LENGTH = 255

    DATA_RECORD_TYPE = 0x00
    END_OF_FILE_RECORD_TYPE = 0x01
    EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE = 0x02
    START SEGMENT ADDRESS RECORD TYPE = 0x03
    EXTENDED_LINEAR_ADDRESS_RECORD_TYPE = 0x04
    START_LINEAR_ADDRESS_RECORD_TYPE = 0x05

    def __init__(self, record_length: int, load_offset: int, record_type: int, data: bytes, checksum: int):
        self.record_length = record_length
        self.load_offset = load_offset
        self.record_type = record_type
        self.data = bytearray(data)
        self.checksum = checksum
        self.actual_checksum = self.calculate_checksum(record_length, load_offset, record_type, data)

    def calculate_checksum(self, record_length: int, load_offset: int, record_type: int, data: bytes) -> int:
        accum = 0
        accum += record_length & 0xff
        accum += load_offset & 0xff
        accum += (load_offset >> 8) & 0xff
        accum += record_type & 0xff
        for ii in range(len(data)):
            t = data[ii] & 0xff
            accum += t
        lowest = accum & 0xff
        chk = (0x100 - lowest) & 0xff
        return chk

    def check_validity(self):
        self.check_record_length()
        self.check_load_offset()

    def check_record_length(self):
        if self.record_length != len(self.data):
            raise ValueError("recordLength != data.length")
        if self.record_length > IntelHexRecord.MAX_RECORD_LENGTH:
            raise ValueError(f"recordLength > {IntelHexRecord.MAX_RECORD_LENGTH}")

    def check_load_offset(self):
        if self.load_offset < 0:
            raise ValueError("loadOffset < 0")
        if self.load_offset > 0xffff:
            raise ValueError("loadOffset > 0xffff")

    @property
    def record_length(self) -> int:
        return self._record_length

    @record_length.setter
    def record_length(self, value: int):
        self._record_length = value

    @property
    def load_offset(self) -> int:
        return self._load_offset

    @load_offset.setter
    def load_offset(self, value: int):
        self._load_offset = value

    @property
    def record_type(self) -> int:
        return self._record_type

    @record_type.setter
    def record_type(self, value: int):
        self._record_type = value

    @property
    def data(self) -> bytes:
        return bytearray(self._data)

    @data.setter
    def data(self, value: bytes):
        self._data = bytearray(value)

    @property
    def checksum(self) -> int:
        return self._checksum

    @checksum.setter
    def checksum(self, value: int):
        self._checksum = value

    @property
    def actual_checksum(self) -> int:
        return self._actual_checksum

    @actual_checksum.setter
    def actual_checksum(self, value: int):
        self._actual_checksum = value

    def get_record_length(self) -> int:
        return self.record_length

    def get_load_offset(self) -> int:
        return self.load_offset

    def get_record_type(self) -> int:
        return self.record_type

    def get_data(self) -> bytes:
        return bytearray(self.data)

    def get_reported_checksum(self) -> int:
        return self.checksum

    def is_reported_checksum_correct(self) -> bool:
        return self.checksum == self.actual_checksum

    def format(self) -> str:
        sb = StringBuilder()
        sb.append(f":{self.record_length:02X}{self.load_offset:04X}{self.record_type:02X}")
        for ii in range(len(self.data)):
            sb.append(f"{self.data[ii]:02X}")
        return sb.toString()

    def __hash__(self) -> int:
        prime = 31
        result = 1
        result *= prime + self.actual_checksum
        result *= prime + self.checksum
        result *= prime + hash(self.data)
        result *= prime + self.load_offset
        result *= prime + self.record_length
        result *= prime + self.record_type
        return result

    def __eq__(self, other):
        if self is other:
            return True
        if other is None:
            return False
        if not isinstance(other, IntelHexRecord):
            return False
        if self.actual_checksum != other.actual_checksum:
            return False
        if self.checksum != other.checksum:
            return False
        if self.data != other.data:
            return False
        if self.load_offset != other.load_offset:
            return False
        if self.record_length != other.record_length:
            return False
        if self.record_type != other.record_type:
            return False
        return True

    def __str__(self) -> str:
        return f"IntelHexRecord(record_length={self.record_length}, load_offset={self.load_offset}, record_type={self.record_type}, data={self.data.hex()}, checksum={self.checksum})"
```

Note that Python does not have direct equivalents for Java's `private` and `public` access modifiers, so I've omitted those. Also, the equivalent of Java's `@Override` annotation is not necessary in Python as it will automatically override methods if they are defined correctly.