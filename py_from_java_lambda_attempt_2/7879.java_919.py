Here is the translation of the Java code into Python:

```Python
class MDString:
    def __init__(self):
        self.name = ""
        self.byte_array = None
        self.byte_string = None
        self.char_type = 0
        self.type_size = 1
        self.crc_pass = False
        self.len_val = 0
        self.crc_val = 0
        self.has_addr = False
        self.addr_val = 0

    def insert(self, builder):
        pass

    def is_unicode(self):
        return self.char_type == '1'

    def get_bytes(self):
        return self.byte_array

    def get_length(self):
        return self.len_val

    def get_name(self):
        return self.name

    def has_address(self):
        return self.has_addr

    def get_address(self):
        return self.addr_val

    def get_string(self, charset8, charset16):
        if not self.byte_string:
            index = 0
            switch_type = self.type_size
            if switch_type == 2:
                byte_string = str.encode(self.byte_array).decode(charset16)
            else:
                byte_string = str.encode(self.byte_array).decode(charset8)

            for i in range(len(byte_string)):
                if byte_string[i] == '\0':
                    byte_string = byte_string[:i]
                    break

        return byte_string

    def crc_pass(self):
        return self.crc_pass

    def parse_internal(self, dmang):
        name = ""
        # Up to this point the following characters have been stripped: '??_C'
        if dmang.get_and_increment() != '@':
            raise MDException("MDString parse error: missing @")
        if dmang.get_and_increment() != '_':
            raise MDException("MDString parse error: missing _")
        char_type = dmang.get_and_increment()
        len_obj = MDEncodedNumber(dmang)
        len_obj.parse()
        self.len_val = int(len_obj.value())
        crc_number = MDEncodedNumber(dmang)
        crc_number.parse()
        self.crc_val = long(crc_number.value())

        switch char_type:
            case '0':  # char string
                self.type_size = 1
                name = "'string'"
                break
            case '1':  # wchar_t string
                self.type_size = 2
                name = "'string'"
                break
            default:
                self.type_size = 1
                name = "MDString: Microsoft string of unknown type: " + char_type
                break

        if (self.len_val % self.type_size) != 0:
            # error... which we are currently ignoring
            pass

        self.parse_byte_array(dmang)

        if dmang.peek() != MDMang.DONE:
            addr_obj = MDEncodedNumber(dmang)
            addr_obj.parse()
            self.addr_val = long(addr_obj.value())
            self.has_addr = True

        if self.len_val <= (32 * self.type_size):
            crc_checker = CrcChecker()
            self.crc_pass = crc_checker.crc_check(self.byte_array, self.crc_val, self.type_size)
        else:
            # Returning true for now, as we do not have the data needed to calculate the CRC.
            self.crc_pass = True

    def parse_byte(self):
        b = 0
        c = dmang.get_and_increment()
        if (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_' or c == '$':
            b = ord(c)
        elif c == '?':
            if dmang.peek() != MDMang.DONE:
                raise MDException("MDString parse error: not enough data")
            c = dmang.get_and_increment()
            if (c >= 'a' and c <= 'z'):
                b = (ord(c) - ord('a') + 0xe1)
            elif (c >= 'A' and c <= 'Z'):
                b = (ord(c) - ord('A') + 0xc1)
            else:
                switch c:
                    case '0':
                        b = ord(',')
                        break
                    case '1':
                        b = ord('/')
                        break
                    case '2':
                        b = ord('\\')
                        break
                    case '3':
                        b = ord(':')
                        break
                    case '4':
                        b = ord('.')
                        break
                    case '5':
                        b = ord(' ')
                        break
                    case '6':
                        b = ord('\n')
                        break
                    case '7':
                        b = ord('\t')
                        break
                    case '8':
                        b = ord("'")
                        break
                    case '9':
                        b = ord('-')
                        break
                    case '$':
                        if dmang.peek() != MDMang.DONE:
                            raise MDException("MDString parse error: not enough data")
                        c = dmang.get_and_increment()
                        if (c < 'A' or c > ('A' + 15)):
                            raise MDException("MDString parse error: invalid hex code:" + c)
                        b = ((ord(c) - ord('A')) << 4)
                        c = dmang.get_and_increment()
                        if (c < 'A' or c > ('A' + 15)):
                            raise MDException("MDString parse error: invalid hex code:" + c)
                        b |= (ord(c) - ord('A'))
                        break
                    default:
                        raise MDException("MDString parse error: invalid code2: " + c)

        else:
            raise MDException("MDString parse error: invalid code1: " + c)

        return b

    def parse_byte_array(self, dmang):
        self.byte_array = bytearray(self.len_val)
        index = 0
        while (dmang.peek() != '@' and index < self.len_val):
            self.byte_array[index] = self.parse_byte()
            index += 1
        dmang.increment()

    class CrcChecker:
        def __init__(self):
            self.crc = 0xffffffffL

        def reflect_bits(self, val):
            i = 0
            new_val = 0L
            for i in range(32):
                new_val >>= 1
                new_val |= val & 0X80000000L
                val <<= 1
            return new_val

        def crc_calc(self, val):
            long_byte = ord(val)
            for i in range(8):
                self.crc <<= 1
                if ((self.crc >> 32) ^ long_byte) & 0x01L:
                    self.crc ^= 0x04c11db7L

        def crc_check(self, bytes, crc_test, size):
            index = 0
            self.crc = 0xffffffffL
            for i in range(len(bytes)):
                if (i % size) == 0 and i > 0:
                    continue
                for j in range(size - 1, -1, -1):
                    self.crc_calc(ord(bytes[i + j]))
            self.crc &= 0xffffffffL
            self.crc = self.reflect_bits(self.crc)
            return (self.crc == crc_test)

class MDEncodedNumber:
    def __init__(self, dmang):
        pass

    def parse(self):
        pass

    @property
    def value(self):
        pass


class MDException(Exception):
    pass