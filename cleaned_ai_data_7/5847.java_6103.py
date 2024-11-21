class DittedBitSequence:
    def __init__(self):
        self.bits = None
        self.dits = None

    @staticmethod
    def popcount(n):
        return bin(n).count('1')

    def init_from_ditted_string_data(self, ditted_bit_data):
        if not isinstance(ditted_bit_data, str):
            raise ValueError("Invalid input")

        ditarray = []
        bitarray = []

        i = 0
        while i < len(ditted_bit_data):
            c1 = ditted_bit_data[i]
            if c1 == '#':
                break

            mode = -1
            mark_offset = None

            for j in range(i + 1, len(ditted_bit_data)):
                c2 = ditted_bit_data[j]

                if c2 == '0' or c2 == '1' or c2 == '.':
                    mode = 1
                    break

                elif c2 == '*':
                    mark_offset = i
                    break

            if mode != -1 and (c1 == 'x' or c1 == '.'):
                mode = 0
                val = int(ditted_bit_data[i + 1:j].replace('.', ''), 16)
                mask = 0xff

                if c2 == '.':
                    mask ^= 0xf0
                elif c2 != '*':
                    val |= (int(c2, 16) << 4)

                bitarray.append((val & 0xff).to_bytes(1, 'big'))
                ditarray.append((mask & 0xff).to_bytes(1, 'byte'))

            else:
                for j in range(i + 8):
                    c = ditted_bit_data[j]
                    if c == '.' or c == '*':
                        val <<= 1
                        mask <<= 1
                        mask |= 1

                    elif c != '0' and c != '1':
                        raise ValueError("Invalid input")

                bitarray.append((val & 0xff).to_bytes(1, 'big'))
                ditarray.append((mask & 0xff).to_bytes(1, 'byte'))

        self.bits = bytearray(bitarray)
        self.dits = bytearray(ditarray)

    def __init__(self, ditted_bit_data):
        if isinstance(ditted_bit_data, str):
            self.init_from_ditted_string_data(ditted_bit_data)
        elif isinstance(ditted_bit_data, DittedBitSequence):
            self.bits = bytes(ditted_bit_data.bits)
            self.dits = bytes(ditted_bit_data.dits)

    def get_value_bytes(self):
        return self.bits

    def get_mask_bytes(self):
        return self.dits

    @staticmethod
    def crc32(data):
        import zlib
        return int(zlib.crc32(data) & 0xffffffff)

    def __hash__(self):
        return DittedBitSequence.crc32(self.get_value_bytes() + self.get_mask_bytes())

    def __eq__(self, other):
        if not isinstance(other, DittedBitSequence):
            return False

        for i in range(len(self.bits)):
            if self.bits[i] != other.bits[i]:
                return False
            if self.dits[i] != other.dits[i]:
                return False

        return True

    def concatenate(self, to_concat):
        res = DittedBitSequence()
        res.bits = bytearray(self.bits + to_concat.get_value_bytes())
        res.dits = bytearray(self.dits + to_concat.get_mask_bytes())

        return res

    def is_match(self, pos, val):
        if pos >= len(self.bits):
            return False
        return (val & self.dits[pos]) == self.bits[pos]

    def set_index(self, index):
        self.index = index

    def get_index(self):
        return self.index

    def get_size(self):
        return len(self.bits)

    def get_num_fixed_bits(self):
        if not hasattr(self, 'dits'):
            return 0
        popcnt = sum(DittedBitSequence.popcount(dit) for dit in self.dits)
        return popcnt

    @staticmethod
    def write_bits(buf, bits, dits):
        buf.write(' ')
        for i in range(128):
            if (dits & (1 << i)) == 0:
                buf.write('.')
            elif bits & (1 << i) != 0:
                buf.write('1')
            else:
                buf.write('0')

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        buf = StringBuffer()
        for chunk in range(0, len(self.bits), 8):
            buf.append(' ')
            dchomp = self.dits[chunk]
            bchomp = self.bits[chunk]
            for i in range(128):
                if (dchomp & (1 << i)) == 0:
                    buf.write('.')
                elif bits & (1 << i) != 0:
                    buf.write('1')
                else:
                    buf.write('0')

        return buf.toString()

    def get_hex_string(self):
        uncompressed = self.__str__()
        parts = uncompressed.split()
        sb = StringBuffer()
        for i, part in enumerate(parts):
            if '.' in part:
                sb.append(part)
                if i != len(parts) - 1:
                    sb.append(' ')
            else:
                hex_byte = format(int(binascii.hexlify(bytes([int(part)])), 2).zfill(8), 'x')
                if len(hex_byte) < 2:
                    hex_byte = '0' + hex_byte
                sb.append("0x")
                sb.append(hex_byte)
                if i != len(parts) - 1:
                    sb.append(' ')

        return sb.toString()

    def restore_xml_data(self, parser):
        try:
            self.init_from_ditted_string_data(parser.getText())
        except ValueError as e:
            raise IOException(str(e))

class StringBuffer:
    def __init__(self):
        self.buf = []

    def append(self, s):
        if isinstance(s, str):
            self.buf.append(s)
        elif hasattr(s, 'toString'):
            self.buf.append(s.toString())

    def toString(self):
        return ''.join(self.buf)

def main():
    # Example usage
    ditted_bit_sequence = DittedBitSequence("0x..d.4de2 ....0000 .1...... 00101101 11101001")
    print(ditted_bit_sequence.get_hex_string())

if __name__ == "__main__":
    main()
