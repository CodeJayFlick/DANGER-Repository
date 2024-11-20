Here is the translation of the Java code into Python:

```Python
class IntelHexMemImage:
    def __init__(self, space, base):
        self.base = base
        self.space = space
        self.range_map = {}
        self.set = set()
        self.partitions = set()

    def has_defined_bytes(self):
        return not self.set.isdisjoint()

    def log(self, line, msg):
        print(f"line: {line}")
        print(f"{msg} (base {self.base})")

    def parse_line(self, line):
        try:
            record = IntelHexRecordReader.read_record(line)
            if not record.reported_checksum_correct():
                return f"WARNINIG: line checksum ({record.reported_checksum()}) is not correct ({record.actual_checksum()})"
            load_offset = record.load_offset()
            data = record.data()

            switcher = {
                0x00: self.parse_data_record,
                0x01: self.parse_end_of_file_record_type,
                0x02: self.parse_extended_linear_address_record_type,
                0x03: self.parse_extended_segment_address_record_type,
                0x04: self.parse_start_linear_address_record_type,
                0x05: self.parse_start_segment_address_record_type
            }
            return switcher.get(record.record_type(), lambda x: f"Impossible record type: {record.format()}")()

        except Exception as e:
            return str(e)

    def parse_data_record(self):
        range_start = self.base + load_offset()
        range_end = self.base + (load_offset() + len(data) - 1)
        if range_end < range_start:
            first_range_end = find_wrap_point(load_offset(), range_end.offset())
            first_range = AddressRangeImpl(range_start, self.base + first_range_end)
            first_data_length = int(first_range_end - load_offset() + 1)
            first_data = bytearray(first_data_length)
            data[:first_data_length].copyto(first_data)
            self.range_map[first_range] = first_data
            self.set.add(first_range)
            second_range_start = self.base + (load_offset() + len(data) - first_data_length)
            second_range = AddressRangeImpl(second_range_start, range_end)
            second_data_length = len(data) - first_data_length
            second_data = bytearray(second_data_length)
            data[first_data_length:].copyto(second_data)
            self.range_map[second_range] = second_data
            self.set.add(second_range)

        else:
            address_range = AddressRangeImpl(range_start, range_end)
            self.range_map[address_range] = data
            self.set.add(address_range)

    def parse_end_of_file_record_type(self):
        pass

    # ... and so on for the other record types ...

    def find_wrap_point(self, start_offset, end_offset):
        left_ptr = start_offset
        right_ptr = end_offset
        while (left_ptr + 1) < right_ptr:
            midpoint = (left_ptr + right_ptr) // 2
            middle = self.base + midpoint
            if middle < range_start:
                right_ptr = midpoint
            else:
                left_ptr = midpoint

    def get_start_eip(self):
        return start_eip

    def get_start_cs(self):
        return start_cs

    def get_start_ip(self):
        return start_ip

    def create_memory(self, creator, prog_file, block_name=None, is_overlay=False, program=None, monitor=None):
        log = MessageLog()
        count = 0
        partitioner = AddressSetPartitioner(set(), range_map, partitions)
        my_range_map = {k: v for k, v in zip(partitioner.get_partitioned_range_map().keys(), partitioner.get_partitioned_range_map().values())}
        for block_range in partitioner:
            iter = iter(my_range_map.keys())
            block_set = set()
            while True:
                try:
                    range_ = next(iter)
                except StopIteration:
                    break
                if block_range.intersects(range_):
                    block_set.add(range_)
            filled = [False] * int(block_range.length())
            data = bytearray(int(block_range.length()))
            for address_range in block_set:
                bytes_ = my_range_map[address_range]
                pos = (int(address_range.min_address().offset()) - int(block_range.min_address().offset()))
                range_check(bytes_, 0, data, pos, len(bytes_))
                data[pos:pos + len(bytes_)].copyto(data)
                for jj in range(len(bytes_)):
                    if filled[pos + jj]:
                        print("OVERWRITE!")
                    filled[pos + jj] = True
            my_range_map.pop(address_range)

        name = block_name if not block_name else self.base.get_address_space().name()
        MemoryBlockUtils.create_initialized_block(program, is_overlay, name,
                                                     block_range.min_address(), io.BytesIO(data), len(data),
                                                     f"Generated by {creator}", prog_file, True, False, log, monitor)

    def range_check(src, src_pos, dest, dest_pos, length):
        if src_pos + length > len(src):
            raise ValueError("src range check failed")
        if dest_pos + length > len(dest):
            raise ValueError("dest range check failed")

class AddressRangeImpl:
    pass

def ub(b):
    return b & 0xff
```

Please note that Python does not have direct equivalent of Java's `switch` statement. Instead, you can use a dictionary to map values to functions or use an if-elif ladder.

Also, the code is quite complex and it may be difficult to translate all the methods without knowing more about their purpose and behavior.