class HighFunctionShellSymbol:
    def __init__(self, id: int, name: str, addr: 'Address', manage):
        super().__init__(id, name, DataType.DEFAULT, True, True, manage)
        try:
            store = VariableStorage(get_program(), addr, 1)
        except InvalidInputException as e:
            store = VariableStorage.UNASSIGNED_STORAGE
        entry = MappedEntry(self, store, None)
        self.add_map_entry(entry)

    def is_global(self):
        return True

    def save_xml(self, buf: 'StringBuilder'):
        buf.append("<function")
        SpecXmlUtils.encode_unsigned_integer_attribute(buf, "id", self.get_id())
        SpecXmlUtils.xml_escape_attribute(buf, "name", self.name)
        SpecXmlUtils.encode_signed_integer_attribute(buf, "size", 1)
        buf.append(">\n")
        AddressXML.build_xml(buf, self.get_storage().get_min_address())
        buf.append("</function>\n")

class MappedEntry:
    def __init__(self, symbol: 'HighFunctionShellSymbol', store: 'VariableStorage', entry):
        self.symbol = symbol
        self.store = store
        self.entry = entry

class VariableStorage:
    UNASSIGNED_STORAGE = None  # todo implement this class in Python

def get_program():
    return "todo"  # todo implement this function to return the program object

