Here is the translation of the given Java code into Python:

```Python
import unittest

class AddressMapDB64BitTest(unittest.TestCase):

    LANGUAGE_64BIT = "sparc:BE:64:default"

    def __init__(self):
        super().__init__()

    @unittest.skip("Not implemented yet")
    def create_test_program(self) -> None:
        program = self.create_program(LANGUAGE_64BIT)
        success = False
        tx_id = program.start_transaction("Define blocks")

        try:
            address_space = program.get_address_factory().get_default_address_space()
            program.set_image_base(address_space.get_address(0x1000000000), True)

            memory = program.get_memory()

            # Block1 is located within first chunk following image base (base 0 allocated)
            memory.create_uninitialized_block("Block1", address_space.get_address(0x2000000000L), 0x100000, False)

            try:
                memory.create_uninitialized_block("Block2", address_space.get_address(0xfffffd000L), 0x4000, False)
                self.fail("Expected MemoryConflictException")
            except MemoryConflictException as e:
                # Expected
                pass

            try:
                memory.create_uninitialized_block("Block2", address_space.get_address(
                    0xfffffffffff00000L), 0x100001, False)
                self.fail("Expected AddressOverflowException")
            except AddressOverflowException as e:
                # Expected
                pass

            # Block2 is at absolute end of space (base 1 allocated)
            memory.create_uninitialized_block("Block2", address_space.get_address(
                0xfffffffffff00000L), 0x100000, False)

            # Block3 spans two (2) memory chunks and spans transition between positive and negative offset values
            # (base 2(end of block) and 3(start of block) allocated)
            memory.create_initialized_block("Block3", address_space.get_address(
                0x7ffffffffff00000L), 0x200000, bytes([0]), None, False)

            success = True

        finally:
            program.end_transaction(tx_id, success)

    def test_key_ranges(self) -> None:
        key_ranges = self.addr_map.get_key_ranges(0, 2**64 - 1, False)
        self.assertEqual(len(key_ranges), 4)

        for i in range(len(key_ranges)):
            kr = key_ranges[i]
            print(f"{self.addr_map.decode_address(kr.min_key)}->{self.addr_map.decode_address(kr.max_key)}")
            if i == 0:
                self.assertEqual(self.addr_map.decode_address(kr.min_key), 0x2000000000L)
                self.assertEqual(self.addr_map.decode_address(kr.max_key), 0x20ffffffffL)
            elif i == 1:
                self.assertEqual(self.addr_map.decode_address(kr.min_key), 0x7fffffff00000000L)
                self.assertEqual(self.addr_map.decode_address(kr.max_key), 0x7fffffffffffffffL)
            elif i == 2:
                self.assertEqual(self.addr_map.decode_address(kr.min_key), 0x8000000000000000L)
                self.assertEqual(self.addr_map.decode_address(kr.max_key), 0x80000000ffffffffL)
            else:
                self.assertEqual(self.addr_map.decode_address(kr.min_key), 0x0ffffffff00000000L)
                self.assertEqual(self.addr_map.decode_address(kr.max_key), 0x0ffffffffffffffffL)

    def test_relocatable_address(self) -> None:
        addr = 0x1000000000
        key = self.addr_map.get_key(addr, False)
        self.assertEqual(key, AddressMap.INVALID_ADDRESS_KEY)

        tx_id = program.start_transaction("New address region")
        try:
            key = self.addr_map.get_key(addr, True)
            self.assertEqual(key, 0x2000000400000000L + 0x1000)
            self.assertEqual(self.addr_map.decode_address(key), addr)
        finally:
            program.end_transaction(tx_id, True)

    def test_absolute_address(self) -> None:
        addr = 0x1000000000
        key = self.addr_map.get_absolute_encoding(addr, False)
        self.assertEqual(key, 0x1000000000000000L)
        self.assertEqual(self.addr_map.decode_address(key), addr)

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the given Java code into Python. It might not be perfect and may require some adjustments to work correctly in your specific use case.