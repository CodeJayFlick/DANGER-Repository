Here is the translation of the given Java code into Python:

```Python
class DittedBitSequence:
    def __init__(self, bits=None, dits=None):
        self.bits = bits if bits else []
        self.dits = dits if dits else []

    @property
    def get_hex_string(self):
        return ''.join(['1' if bit & 0x80 > 0 else '0'
                        for byte in self.bits]
                       + ['.' if dit & 0x01 == 0 else '1'
                          for dit in self.dits])

    @property
    def get_num_uncertain_bits(self):
        return sum(1 for bit, dit in zip(self.bits, self.dits)
                   if (bit & 0x80 > 0) != (dit & 0x01 == 0))

    @property
    def get_least_upper_bound(self):
        fixed = sum(1 for byte in self.bits if byte & 0x80 > 0)
        uncertain = len(self.dits) - fixed
        return f"{'.' * fixed}{'f' * (8 - fixed)}"

class TestDittedBitSequence:
    def test_ditted_bit_sequence_constructor(self):
        bits = bytes([0xe0])
        dits = bytes([0xe7])

        seq = DittedBitSequence(bits, dits)
        assert seq.get_hex_string == "111..000"

    def test_get_num_uncertain_bits(self):
        seq1 = DittedBitSequence(bytes([0xff]), bytes([0xff]))
        seq2 = DittedBitSequence(bytes([0x00]), bytes([0xff]))

        seq3 = DittedBitSequence(b'\xa0', b'\x55')
        assert seq3.get_num_uncertain_bits == 4

    def test_get_least_upper_bound(self):
        zeros = DittedBitSequence(b'0', b'\xff')
        ones = DittedBitSequence(b'\xff', b'\xff')

        evens = DittedBitSequence(b'0', b'\x55')
        odds = DittedBitSequence(b'\xff', b'\xaa')

        merge1 = DittedBitSequence(ones, zeros)
        assert merge1.get_least_upper_bound == "........"
        assert merge1.get_num_fixed_bits() == 0
        assert merge1.get_num_uncertain_bits() == 8

        merge2 = DittedBitSequence(odds, evens)
        assert merge2.get_least_upper_bound == ".0.0.0.0"
        assert merge2.get_num_fixed_bits() == 4
        assert merge2.get_num_uncertain_bits() == 4

    def test_get_num_initial_fixed_bits(self):
        uninitialized = DittedBitSequence()
        for _ in range(3):
            assert uninitialized.get_num_initial_fixed_bits(_) == 0

        length_zero = DittedBitSequence(b'')
        for _ in range(2):
            assert length_zero.get_num_initial_fixed_bits(_) == 0

        no_dits = DittedBitSequence("0x00ff")
        for i in range(4):
            if i < 3:
                assert no_dits.get_num_initial_fixed_bits(i) == 8
            else:
                assert no_dits.get_num_initial_fixed_bits(i) == 0

        some_dits = DittedBitSequence("0.0.0.0.1.1.1.1.")
        for i in range(4):
            if i < 3:
                assert some_dits.get_num_initial_fixed_bits(i) == 8
            else:
                assert some_dits.get_num_initial_fixed_bits(i) == 0

        all_dits = DittedBitSequence("................")
        for _ in range(4):
            assert all_dits.get_num_initial_fixed_bits(_) == 0