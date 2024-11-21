class FindReferencesTableModel:
    def __init__(self, from_addr: 'Address', provider=None, prog=None):
        self.from_addr = from_addr
        if provider and prog:
            super().__init__(from_addr.__str__(), provider, prog)

    def set_alignment(self, alignment):
        pass  # equivalent to Java's setAlignment

class ReferenceFromAddressTableColumn:
    pass  # equivalent to the abstract class in Java

class ReferenceToAddressTableColumn:
    pass  # equivalent to the abstract class in Java

class ReferenceFromLabelTableColumn:
    pass  # equivalent to the abstract class in Java

class ReferenceFromPreviewTableColumn:
    pass  # equivalent to the abstract class in Java

class ReferenceToPreviewTableColumn:
    pass  # equivalent to the abstract class in Java

def initialize_unaligned_list(self, accumulator: 'Accumulator', monitor=None):
    if not monitor or isinstance(monitor, CancelledException):
        return
    ProgramMemoryUtil.load_direct_reference_list(get_program(), self.alignment, from_addr=self.from_addr,
                                                  address_set=self.address_set, accumulator=accumulator, monitor=monitor)

def get_search_address_set(self) -> 'AddressSetView':
    return self.address_set

def get_address(self) -> 'Address':
    return self.from_addr
