class OffcutReferenceCountToAddressTableColumn:
    def get_column_display_name(self, settings):
        return self.get_column_name()

    def get_column_name(self):
        return "Offcut Reference Count"

    def get_value(self, address: int, program: object) -> int:
        count = 0
        if isinstance(address, int):  # isMemoryAddress()
            code_unit = program.listing().get_code_unit_containing(address)
            if code_unit is not None:
                set = AddressSet(code_unit.get_min_address(), code_unit.get_max_address())
                set.delete_range(address, address)  # deleteRange
                reference_manager = program.reference_manager()
                it = reference_manager.get_reference_destination_iterator(set, True)
                while it.has_next():
                    it.next()
                    count += 1
        return count

class AddressSet:
    def __init__(self, min_address: int, max_address: int):
        self.min_address = min_address
        self.max_address = max_address

    def delete_range(self, start: int, end: int) -> None:
        pass  # not implemented in Python

class ReferenceManager:
    def get_reference_destination_iterator(self, set: object, reverse: bool) -> object:
        pass  # not implemented in Python
