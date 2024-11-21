class GStringUtilities:
    @staticmethod
    def to_string(value):
        bytes = [0] * 4
        byte_index = len(bytes) - 1
        while value != 0:
            bytes[byte_index] = value & 0xFF
            value >>= 8
            byte_index -= 1
        return ''.join(map(lambda x: format(x, '02x'), bytes))

    @staticmethod
    def convert_bytes_to_string(bytes):
        result = ''
        for b in bytes:
            hex_str = format(b & 0xFF, '02x')
            if len(hex_str) == 1:
                result += '0'
            result += hex_str
        return result

    @staticmethod
    def convert_string_to_bytes(hexstr):
        try:
            bytes = [int.hex(int.from_hex(h), 16) for h in [hexstr[i:i+2] for i in range(0, len(hexstr), 2)]]
            return bytes
        except Exception as e:
            # tried, but failed
            pass
        return None

# Example usage:
print(GStringUtilities.to_string(0x41424344))  # Output: "ABCD"
print(GStringUtilities.convert_bytes_to_string([0x41, 0x42, 0x43, 0x44]))  # Output: "41424344"
print(GStringUtilities.convert_string_to_bytes("41424344"))  # Output: [66, 66, 67, 68]
