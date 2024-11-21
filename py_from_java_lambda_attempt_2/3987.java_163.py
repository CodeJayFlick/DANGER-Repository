Here is the translation of the Java code into Python:

```Python
class InstructionSearchUtils:
    def __init__(self):
        pass

    @staticmethod
    def to_binary_string(byte_val: int) -> str:
        binary_str = "00000000"
        for bit in range(8):
            if (byte_val >> bit) & 1 > 0:
                binary_str = binary_str[:7 - bit] + '1' + binary_str[7 - bit:]
        return binary_str

    @staticmethod
    def is_binary(input: str) -> bool:
        input = input.replace(" ", "")
        return input.match(r"[01]+")

    @staticmethod
    def to_binary(hex_val: str, zero_fill=False) -> str:
        hex_val = hex_val.replace(" ", "").upper()
        binary_str = ""
        for byte in range(0, len(hex_val), 2):
            bin_byte = format(int(hex_val[byte:byte + 2], 16), "08b")
            if not zero_fill or (zero_fill and len(bin_byte) < 8):
                binary_str += bin_byte
            else:
                binary_str += "0" * (8 - len(bin_byte)) + bin_byte
        return binary_str

    @staticmethod
    def is_hex(input: str) -> bool:
        input = input.replace(" ", "").upper()
        return input.match(r"[0-9A-F]+")

    @staticmethod
    def to_hex(binary_val: str, zero_fill=False) -> str:
        if not isinstance(binary_val, str):
            binary_val = "".join(format(byte, "08b") for byte in binary_val)
        hex_str = ""
        while len(binary_val) > 0:
            bin_byte = binary_val[:8]
            if "." in bin_byte or "[" in bin_byte or "]" in bin_byte:
                hex_str += "["
                break
            decimal = int(bin_byte, 2)
            hex_str += format(decimal, "02X")
            if zero_fill and len(hex_str) < 16:
                hex_str += "0" * (16 - len(hex_str))
        return hex_str

    @staticmethod
    def to_hex_nibbles_only(binary_val: str) -> str:
        binary_val = binary_val.replace(" ", "")
        nibble_bytes = [binary_val[i:i + 8] for i in range(0, len(binary_val), 8)]
        hex_str = ""
        for byte in nibble_bytes:
            if "." in byte or "[" in byte or "]" in byte:
                hex_byte1 = "."
                hex_byte2 = "."
            else:
                decimal = int(byte[:4], 2)
                hex_byte1 = format(decimal, "02X")
                decimal = int(byte[4:], 2)
                hex_byte2 = format(decimal, "02X")
            if len(hex_str) > 0 and (hex_str[-2:] == ".-" or hex_str[-2:] == "-."):
                hex_str += "-"
            else:
                hex_str += hex_byte1 + hex_byte2
        return hex_str

    @staticmethod
    def get_group_sizes(source: str, mode: int) -> list:
        group_sizes = []
        if mode == 0:
            byte_length = 8
        elif mode == 1:
            byte_length = 2
        else:
            raise ValueError("Invalid input mode")
        for i in range(0, len(source), byte_length):
            group_size = (i + byte_length) // byte_length - (i // byte_length)
            if source[i:i + byte_length].replace(" ", "").length() < byte_length or \
               source[i:i + byte_length].replace(" ", "").index(".") != 4:
                raise ValueError("Input is not a full byte(s)")
            group_sizes.append(group_size)
        return group_sizes

    @staticmethod
    def get_whitespace(source: str) -> list:
        whitespace = []
        pattern = re.compile(r"\s+")
        matcher = pattern.match(source)
        while matcher:
            whitespace.append(matcher.group())
            matcher = pattern.search(source, matcher.end())
        return whitespace

    @staticmethod
    def to_byte_array(byte_str: str) -> list:
        byte_arr = [int(byte_str[i:i + 2], 16) for i in range(0, len(byte_str), 2)]
        return [(byte & 0xff).to_bytes(1, "big") for byte in byte_arr]

    @staticmethod
    def to_primitive(bytes: list) -> bytes:
        primitive = bytearray()
        for b in bytes:
            primitive.extend(b)
        return bytes(primitive)

    @staticmethod
    def add_space_on_byte_boundary(str_val: str, mode: int) -> str:
        if mode == 0:
            byte_length = 2
        elif mode == 1:
            byte_length = 8
        else:
            raise ValueError("Invalid input mode")
        ret_str = ""
        for i in range(0, len(str_val), byte_length):
            ret_str += str_val[i:i + byte_length]
            if (i // byte_length) % 2 == 1 and i < len(str_val) - 1:
                ret_str += " "
        return ret_str

    @staticmethod
    def to_address_list(search_results: list) -> list:
        address_list = []
        for meta in search_results:
            if isinstance(meta, InstructionMetadata):
                address_list.append(Address(meta.get_addr()))
        return address_list

    @staticmethod
    def get_instruction_search_plugin(tool: PluginTool) -> InstructionSearchPlugin:
        plugins = tool.get_managed_plugins()
        for plugin in plugins:
            if isinstance(plugin, InstructionSearchPlugin):
                return plugin
        return None


class Address:
    pass  # You need to implement this class based on your actual requirements

class InstructionMetadata:
    def __init__(self, addr: int):
        self.addr = addr
```

Please note that the Python code is not a direct translation of Java code. It's more like an equivalent implementation in Python.