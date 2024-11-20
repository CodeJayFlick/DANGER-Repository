Here is the translation of the Java code into Python:

```Python
import array

class Base43:
    ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"
    INDEXES = {ord(c): i for i, c in enumerate(ALPHABET)}

    @staticmethod
    def encode(input_bytes):
        if len(input_bytes) == 0:
            return ""

        temp = bytearray(len(input_bytes) * 2)
        j = len(temp)

        zero_count = 0
        while zero_count < len(input_bytes) and input_bytes[zero_count] == 0:
            zero_count += 1

        start_at = zero_count
        for i in range(start_at, len(input_bytes)):
            mod43 = Base43.divmod43(input_bytes, i)
            if input_bytes[i] == 0:
                continue
            temp[j - 1] = ALPHABET[mod43].encode('ascii')
            j -= 1

        while j < len(temp) and temp[j-1] == ALPHABET[0]:
            j -= 1

        for _ in range(zero_count):
            temp[j - 1] = ALPHABET[0]
            j -= 1

        return temp[:j].decode('ascii')

    @staticmethod
    def decode(input_str):
        if len(input_str) == 0:
            return bytearray()

        input_bytes = array.array('b', [ord(c) for c in input_str])
        zero_count = 0
        while zero_count < len(input_bytes) and input_bytes[zero_count] == ord(ALPHABET[0]):
            zero_count += 1

        temp = bytearray(len(input_str))
        j = len(temp)

        start_at = zero_count
        for i in range(start_at, len(input_bytes)):
            mod256 = Base43.divmod256(input_bytes, i)
            if input_bytes[i] == ord(ALPHABET[0]):
                continue
            temp[j - 1] = mod256
            j -= 1

        while j < len(temp) and temp[j-1] == 0:
            j -= 1

        return temp[:j].tobytes()

    @staticmethod
    def divmod43(number, start_at):
        remainder = 0
        for i in range(start_at, len(number)):
            digit256 = number[i]
            temp = (remainder * 256 + digit256) % 43
            number[i] = int(temp / 43)
            remainder = temp % 43
        return chr(remainder)

    @staticmethod
    def divmod256(number43, start_at):
        remainder = 0
        for i in range(start_at, len(number43)):
            digit58 = number43[i]
            temp = (remainder * 43 + digit58) % 256
            number43[i] = int(temp / 43)
            remainder = temp % 256
        return chr(remainder)

    @staticmethod
    def copy_of_range(source, from_, to_):
        range_ = bytearray(to_ - from_)
        source.tofile(range_, str(from_), 'b')
        return range_.tobytes()
```

Please note that Python does not have direct equivalent of Java's `System.arraycopy` and `Arrays.fill`. Instead, we use the built-in array module to create a new byte array and then copy elements from one array to another.