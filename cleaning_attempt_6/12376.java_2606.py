class RepeatCountDataType:
    def __init__(self, repeat_data_type):
        self.repeat_data_type = repeat_data_type

    def get_all_components(self, buf):
        try:
            n = (buf.get_byte(0) & 0xff) * 16 + (buf.get_byte(1) & 0xff) + 1
            comps = [None] * n
            comps[0] = {'name': 'Size', 'length': 2, 'offset': 0}
            count_size = 2
            buf.advance(count_size)
            for i in range(1, n):
                dti = self.repeat_data_type.get_instance(buf)
                if dti is None:
                    print(f"ERROR: problem with data at {buf.address}")
                    return None
                len_ = dti.length()
                comps[i] = {'name': f'repDT{i}', 'length': len_, 'offset': count_size}
                buf.advance(len_)
            return comps

        except (MemoryAccessException, AddressOverflowException, AddressOutOfBoundsException) as e:
            print(f"ERROR: problem with data at {buf.address}")
            return None


class MemBuffer:
    def __init__(self):
        self.memory = None
        self.address = 0

    def get_byte(self, offset):
        pass

    def advance(self, length):
        pass


def main():
    repeat_data_type = 'some data type'
    buf = MemBuffer()
    rcdt = RepeatCountDataType(repeat_data_type)
    comps = rcdt.get_all_components(buf)


if __name__ == "__main__":
    main()

