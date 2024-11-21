Here is the translation of the Java code into Python:

```Python
class DataUtilities:
    def __init__(self):
        pass

    @staticmethod
    def is_valid_data_type_name(name: str) -> bool:
        if name is None or len(name) == 0:
            return False
        for i in range(len(name)):
            c = name[i]
            # Don't allow control characters, but otherwise accept as much as possible
            #   a) allow spaces and punctuation
            #   b) allow unicode characters (including supplemental characters)
            if not Character.is_iso_control(c):
                return True
        return False

    @staticmethod
    def get_data_at_location(loc: 'ProgramLocation') -> 'Data':
        if loc is None:
            return None
        addr = loc.get_address()
        listing = loc.get_program().get_listing()
        data_containing = listing.get_data_containing(addr)
        if data_containing is None:
            return None
        data_at_addr = data_containing.get_component(loc.get_component_path())
        return data_at_addr

    @staticmethod
    def get_max_address_of_undefined_range(program: 'Program', addr: Address) -> Address:
        listing = program.get_listing()
        data = listing.get_data_at(addr)
        if data is None or not Undefined.is_undefined(data.get_data_type()):
            return None
        end_of_range_addr = data.get_max_address()

        block = program.get_memory().get_block(addr)
        if block is None:
            return None
        limit_addr = block.get_end()
        cu = data
        while (cu is not None) and (cu.get_address().compareTo(limit_addr) <= 0):
            end_of_range_addr = cu.get_max_address()
            cu = listing.get_defined_code_unit_after(end_of_range_addr)
        if cu is None:
            return limit_addr
        return end_of_range_addr

    @staticmethod
    def find_first_conflicting_address(program: 'Program', addr: Address, length: int,
                                         ignore_undefined_data: bool) -> Address:
        addr_set = set(range(addr, addr + length))
        defined_data_iter = program.get_listing().get_defined_data(addr_set, True)
        data = None
        while defined_data_iter.has_next():
            d = defined_data_iter.next()
            if not ignore_undefined_data or not Undefined.is_undefined(d.get_data_type()):
                data = d
                break

        instruction_iter = program.get_listing().get_instructions(addr_set, True)
        instruction = instruction_iter.has_next() and instruction_iter.next()

        if data is None and instruction is None:
            return None
        if data is None:
            return instruction.get_min_address()
        if instruction is None:
            return data.get_min_address()
        addr1 = data.get_min_address()
        addr2 = instruction.get_address()
        if addr1.compareTo(addr2) < 0:
            return addr1
        return addr2

    @staticmethod
    def is_undefined_range(program: 'Program', start_addr: Address, end_addr: Address) -> bool:
        block = program.get_memory().get_block(start_addr)
        # Start and end address must be in the same block of memory.
        if block is None or not block.contains(end_addr):
            return False
        if start_addr.compareTo(end_addr) > 0:
            return False

        listing = program.get_listing()
        data = listing.get_data_containing(start_addr)
        if data is None or not Undefined.is_undefined(data.get_data_type()):
            return False
        max_addr = data.get_max_address()

        while max_addr.compareTo(end_addr) < 0:
            code_unit = listing.get_defined_code_unit_after(max_addr)
            if code_unit is None:
                return True

            min_addr = code_unit.get_min_address()
            if min_addr.compareTo(end_addr) > 0:
                return True
            if not isinstance(code_unit, Data) or not Undefined.is_undefined((code_unit).get_data_type()):
                return False
            max_addr = code_unit.get_max_address()

        return True

class ProgramLocation:
    def __init__(self):
        pass

    @property
    def program(self):
        # todo: implement this property
        raise NotImplementedError("Program not implemented")

    @property
    def address(self):
        # todo: implement this property
        raise NotImplementedError("Address not implemented")

    @property
    def component_path(self):
        # todo: implement this property
        raise NotImplementedError("Component path not implemented")
```

Note that the `Character`, `Undefined` and other classes are missing in Python. You may need to create them or use existing ones based on your requirements.

Also, note that I've used type hints for better readability but it's up to you whether you want to include those in your actual code.