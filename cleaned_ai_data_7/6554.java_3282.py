class AddressMapDB32BitTest:
    def __init__(self):
        pass

    def create_test_program(self) -> dict:
        program = {"start_transaction": lambda: None,
                   "get_address_factory": lambda: {"default_address_space": 0x100000},
                   "create_uninitialized_block": lambda name, address, size, initialized: None}

        try:
            space = self.get_address_factory()["default_address_space"]
            image_base = program["set_image_base"](space + 0x200000, True)
            memory = {"create_uninitialized_block": lambda name, address, size, initialized: None}
            
            # Block1 is located within first chunk following image base
            memory["create_uninitialized_block"]("Block1", space + 0x200000, 0x100000, False)

            try:
                memory["create_uninitialized_block"]("Block2", space + 0xfff00, 0x1000, False)
                assert False, "Expected MemoryConflictException"
            except Exception as e:
                pass

            try:
                self.get_address_factory()[space + 0x100000000L]
                assert False, "Expected AddressOutOfBoundsException"
            except Exception as e:
                pass
            
            try:
                memory["create_uninitialized_block"]("Block2", space + 0xfff00000, 0x100001, False)
                assert False, "Expected AddressOverflowException"
            except Exception as e:
                pass

            # Block2 is at absolute end of space
            memory["create_uninitialized_block"]("Block2", space + 0xfff00000, 0x100000, False)

        finally:
            program["end_transaction"](True)
        
        return {"program": program}

    def test_key_ranges(self):
        key_ranges = self.addr_map.get_key_ranges(0, 0xffffffffffffffff, False)
        assert len(key_ranges) == 2  # split due to image base

        kr = key_ranges[0]
        assert addr_map.decode_address(kr.min_key) == 0x0
        assert addr_map.decode_address(kr.max_key) == 0x0fffff
        
        kr = key_ranges[1]
        assert addr_map.decode_address(kr.min_key) == 0x100000
        assert addr_map.decode_address(kr.max_key) == 0x0ffffffff

        try:
            self.program["set_image_base"](0, False)
        except Exception as e:
            print(e.stacktrace())
            assert False, str(e)

        key_ranges = self.addr_map.get_key_ranges(0, 0xffffffffffffffff, False)
        assert len(key_ranges) == 1
        
        kr = key_ranges[0]
        assert addr_map.decode_address(kr.min_key) == 0x0
        assert addr_map.decode_address(kr.max_key) == 0x0ffffff

    def test_relocatable_address(self):
        addr = 0x100000
        key = self.addr_map.get_key(addr, False)
        assert key == 0x2000000000000000 + 0x0
        assert addr_map.decode_address(key) == addr
        
        addr = 0x120000
        key = self.addr_map.get_key(addr, False)
        assert key == 0x2000000000000000 + 0x20000
        assert addr_map.decode_address(key) == addr

    def test_absolute_address(self):
        addr = 0x100000
        key = self.addr_map.get_absolute_encoding(addr, False)
        assert key == 0x1000000000000000 + 0x100000
        assert addr_map.decode_address(key) == addr
        
        addr = 0x120000
        key = self.addr_map.get_absolute_encoding(addr, False)
        assert key == 0x1000000000000000 + 0x120000
        assert addr_map.decode_address(key) == addr

if __name__ == "__main__":
    test = AddressMapDB32BitTest()
    program = test.create_test_program()["program"]
