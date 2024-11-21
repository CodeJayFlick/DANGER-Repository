Here is the translation of the given Java code into Python:

```Python
class IntelHexRecord:
    def __init__(self, record_length, address, offset, data, checksum):
        self.record_length = record_length
        self.address = address
        self.offset = offset
        self.data = data
        self.checksum = checksum

def read_record(hex_string):
    # Assuming the hex string is in the format ":<record_length><address><data>"
    parts = hex_string[1:].split(":")
    record_length, address, data = int(parts[0], 16), int(parts[1], 16), bytes.fromhex("".join([part.lstrip().rstrip() for part in parts[2:]]))
    return IntelHexRecord(len(data) + 3, address, 0, data, sum(bytearray(data)) % 256)

def test_basic():
    raw_record = IntelHexRecord(7, 768, 0, b'\x02\x33\x7a', 30)
    read_record_string = ":030000002337A1E"
    read_record = read_record(read_record_string)
    assert raw_record == read_record

if __name__ == "__main__":
    test_basic()
```

This Python code defines a class `IntelHexRecord` to represent an Intel Hex record, and two functions: one to read an Intel Hex record from a string representation of the record, and another function (`test_basic`) that tests this functionality.