Here is the translation of the given Java code into Python:

```Python
class MappedEntry:
    def __init__(self, sym):
        self.sym = sym

    def restore_xml(self, parser):
        function = self.sym.function
        program = function.get_function().get_program()
        addr_factory = function.get_address_factory()

        addrel = parser.start("addr")
        sz = self.sym.type.length
        if sz == 0:
            raise PcodeXMLException(f"Invalid symbol {self.sym.name} with 0-sized data-type")

        try:
            var_addr = AddressXML.read_xml(addrel, addr_factory)
            spc = var_addr.get_address_space()
            if (spc is None) or (spc.type != "VARIABLE"):
                self.storage = VariableStorage(program, var_addr, sz)
            else:
                self.storage = function.read_xml_varnode_pieces(addrel, var_addr)

        except InvalidInputException as e:
            raise PcodeXMLException(f"Invalid storage: {e}")

        parser.end(addrel)

        self.parse_range_list(parser)

    def save_xml(self, buf):
        logicalsize = 0
        type_length = self.sym.type.length
        if type_length != self.storage.size and isinstance(self.sym.type, AbstractFloatDataType):
            logicalsize = type_length

        AddressXML.build_xml(buf, self.storage.get_varnodes(), logicalsize)
        self.build_range_list_xml(buf)

    def get_storage(self):
        return self.storage

    def get_size(self):
        return self.storage.size

    def is_read_only(self):
        addr = self.storage.min_address
        if addr is None:
            return False

        program = self.sym.get_program()
        block = program.memory.block(addr)
        if block is not None:
            readonly = not block.writeable
            # Check references to the variable
            ref_iter = program.reference_manager.references_to(addr)
            count = 0
            while ref_iter.has_next() and count < 100:
                ref = ref_iter.next()
                if ref.reference_type.is_write():
                    return False

        return readonly

    def is_volatile(self):
        addr = self.storage.min_address
        if addr is None:
            return False

        program = self.sym.get_program()
        language = program.language
        if language.is_volatile(addr):
            return True

        block = program.memory.block(addr)
        return block is not None and block.volatile


class VariableStorage:
    def __init__(self, program, var_addr, sz):
        self.program = program
        self.var_addr = var_addr
        self.size = sz


class PcodeXMLException(Exception):
    pass

AddressXML.build_xml(buf, storage.get_varnodes(), logicalsize)
```

Note: This translation assumes that the `AbstractFloatDataType`, `HighSymbol`, `Program`, `ReferenceIterator`, and other classes are defined elsewhere in your Python code.