class DataUtilitiesTest:
    def __init__(self):
        pass

    @staticmethod
    def is_undefined_range(program, start_address, end_address):
        if (start_address.get_offset() >= 0x00 and start_address.get_offset() <= 0xff) or \
           (end_address.get_offset() >= 0x00 and end_address.get_offset() <= 0xff):
            return True
        elif start_address.get_offset() == 0xe7 and end_address.get_offset() in [0xe8, 0xeb]:
            return True
        elif start_address.get_offset() == 0xe9 and end_address.get_offset() in [0xec, 0xef]:
            return True
        elif start_address.get_offset() >= 0xf1:
            if end_address.get_offset() < 0xf4 or (end_address.get_offset() > 0xfa):
                return False
            else:
                return True
        elif start_address.get_offset() == 0xfc and end_address.get_offset() in [0xfd, 0xff]:
            return True
        elif start_address.get_offset() < 0x100 or (end_address.get_offset() > 0x3ff):
            if start_address.get_offset() >= 0x300:
                return False
            else:
                return True
        else:
            return False

    @staticmethod
    def get_max_undefined_range(program, address):
        if address.get_offset() < 0x100 or (address.get_offset() > 0x3ff and address.get_offset() >= 0x300):
            return None
        elif address.get_offset() in [0xf1, 0xf2]:
            return None
        else:
            return address

    def setUp(self):
        pass

    @staticmethod
    def create_program():
        program = ProgramTestDouble()
        program.set_address_factory(AddressFactory())
        program.set_listing(ListingStub())
        program.set_memory(MemoryStub())
        return program


class MemoryBlockStub:
    def __init__(self, address):
        self.address = address

    def get_start(self):
        if 0 <= self.address.get_offset() % 256 < 100 or \
           (self.address.get_offset() >= 300 and self.address.get_offset() % 256 < 4) or \
           self.address.get_offset() in [0xf1, 0xf2]:
            return None
        else:
            return self.address

    def get_end(self):
        if 0 <= self.address.get_offset() % 256 < 100 or \
           (self.address.get_offset() >= 300 and self.address.get_offset() % 256 < 4) or \
           self.address.get_offset() in [0xf1, 0xf2]:
            return None
        else:
            if self.address.get_offset() <= 0xeb:
                return addr(0xeb)
            elif self.address.get_offset() >= 0xe7 and self.address.get_offset() % 256 < 4 or \
                 (self.address.get_offset() > 0xff):
                return None
            else:
                return self.address

    def contains(self, address):
        if 0 <= self.address.get_offset() % 256 < 100 or \
           (self.address.get_offset() >= 300 and self.address.get_offset() % 256 < 4) or \
           self.address.get_offset() in [0xf1, 0xf2]:
            return False
        else:
            if address.get_offset() <= 0xeb:
                return True
            elif (self.address.get_offset() >= 0xe7 and self.address.get_offset() % 256 < 4) or \
                 (address.get_offset() > 0xff):
                return False
            else:
                return True


class DataStub:
    def __init__(self, address):
        self.address = address

    def get_address(self):
        if 0 <= self.address.get_offset() % 256 < 100 or \
           (self.address.get_offset() >= 300 and self.address.get_offset() % 256 < 4) or \
           self.address.get_offset() in [0xf1, 0xf2]:
            return None
        else:
            if self.address.get_offset() <= 0xeb:
                return addr(0xeb)
            elif (self.address.get_offset() >= 0xe7 and self.address.get_offset() % 256 < 4) or \
                 (self.address.get_offset() > 0xff):
                return None
            else:
                return self.address


class ProgramTestDouble:
    def __init__(self):
        pass

    def get_address_factory(self):
        return AddressFactory()

    def get_listing(self):
        return ListingStub()

    def get_memory(self):
        return MemoryStub()


class AddressFactory:
    def __init__(self):
        pass

    @staticmethod
    def get_default_address_space():
        return DefaultAddressSpace()


def addr(offset):
    return address_factory.get_default_address_space().get_address(offset)


if __name__ == "__main__":
    test = DataUtilitiesTest()
