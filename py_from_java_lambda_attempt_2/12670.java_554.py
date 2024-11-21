Here is the translation of the Java code into Python:

```Python
class Scalar:
    def __init__(self, bit_length: int, value: int, signed: bool):
        self.signed = signed
        if not (bit_length == 0 and value == 0) and (1 <= bit_length <= 64):
            raise ValueError("Bit length must be >= 1 and <= 64")
        self.bit_length = bit_length
        self.value = value & ((1 << bit_length) - 1)

    def is_signed(self):
        return self.signed

    @classmethod
    def new_scalar(cls, bit_length: int, value: int, signed: bool):
        return cls(bit_length, value, signed)

    def get_signed_value(self):
        if self.value == 0:
            return 0
        if test_bit(self.bit_length - 1):
            return (self.value | ((~((1 << self.bit_length) - 1)) & ((1 << self.bit_length) - 1))) ^ (~((1 << self.bit_length) - 1))
        return self.value

    def get_unsigned_value(self):
        if self.value == 0:
            return 0
        return (self.value & ((1 << self.bit_length) - 1))

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value: int):
        self._value = value & ((1 << self.bit_length) - 1)

    def get_bit_masks(self):
        bit_masks = [0]
        for i in range(64):
            bit_masks.append(bit_masks[-1] * 2 + 1)
        return bit_masks

    @staticmethod
    def test_bit(bit_position: int, value: int):
        if bit_position < 0 or bit_position >= len(Scalar.get_bit_masks()):
            raise ValueError("Bit position out of range")
        return (value & Scalar.get_bit_masks()[bit_position]) != 0


class BigInteger:
    def __init__(self, signum: int, data: bytes):
        self.signum = signum
        self.data = data

    @property
    def value(self):
        if self.signum < 0:
            return -int.from_bytes(self.data[::-1], 'big')
        else:
            return int.from_bytes(self.data[::-1], 'big')

    def __str__(self):
        return f"BigInteger({self.value})"


def main():
    scalar = Scalar(32, 12345678901234567890, True)
    print(scalar.get_signed_value())
    print(scalar.get_unsigned_value())

if __name__ == "__main__":
    main()
```

Please note that the `get_bit_masks` method is not a part of the original Java code. It was added to simplify the translation process and make it more Pythonic.