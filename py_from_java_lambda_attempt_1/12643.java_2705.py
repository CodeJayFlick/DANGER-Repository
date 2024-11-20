Here is the translation of the given Java code into equivalent Python:

```Python
class JumpTable:
    def __init__(self):
        self.preferred_space = None
        self.op_address = None
        self.address_table = []
        self.label_table = []
        self.load_tables = []
        self.override = None

    @staticmethod
    def translate_overlay_address(addr, preferred_space):
        if addr is not None and isinstance(preferred_space, OverlayAddressSpace) and preferred_space.isOverlaySpace():
            return preferred_space.get_overlay_address(addr)
        return addr

    class LoadTable:
        def __init__(self):
            self.addr = None
            self.size = 0
            self.num = 0

        @property
        def get_addr(self):
            return self.addr

        @property
        def get_size(self):
            return self.size

        @property
        def get_num(self):
            return self.num

    class BasicOverride:
        def __init__(self, destlist):
            self.dest_list = list(destlist)

        @property
        def get_destinations(self):
            return self.dest_list

        def build_xml(self, buf):
            buf.write("<basicoverride>\n")
            for addr in self.dest_list:
                buf.write(f"<dest{AddressXML.append_attributes(buf, addr)}</dest>\n")
            buf.write("</basicoverride>\n")

    @staticmethod
    def read_xml(parser, addr_factory):
        el = parser.start("jumptable")
        try:
            a_table = []
            l_table = []
            ld_table = []

            if not parser.peek().is_start():  # Empty jumptable
                return

            addrel = parser.start("addr")
            switch_addr = JumpTable.translate_overlay_address(AddressXML.read_xml(addrel, addr_factory), preferred_space)
            parser.end(addrel)

            while parser.peek().is_start():
                if parser.peek().name == "dest":
                    subel = parser.start("dest")
                    case_addr = JumpTable.translate_overlay_address(AddressXML.read_xml(subel, addr_factory), preferred_space)
                    a_table.append(case_addr)
                    s_label = subel.get_attribute("label")
                    if s_label is not None:
                        label = int(s_label)
                        l_table.append(label)
                    parser.end(subel)

                elif parser.peek().name == "loadtable":
                    loadtable = LoadTable()
                    loadtable.restore_xml(parser, addr_factory)
                    ld_table.append(loadtable)

                else:
                    parser.discard_subtree()

            op_address = switch_addr
            address_table = a_table.copy()
            label_table = l_table.copy()
            load_tables = ld_table.copy()

        finally:
            parser.end(el)

    def build_xml(self, buf):
        buf.write("<jumptable>\n")
        AddressXML.build_xml(buf, self.op_address)
        buf.write('\n')
        if len(address_table) > 0:
            for addr in address_table:
                buf.write(f"<dest{AddressXML.append_attributes(buf, addr)}</dest>\n")

        if override is not None:
            override.build_xml(buf)

        buf.write("</jumptable>\n")

    @property
    def get_switch_address(self):
        return self.op_address

    @property
    def get_cases(self):
        return address_table.copy()

    @property
    def get_label_values(self):
        return label_table.copy()

    @property
    def get_load_tables(self):
        return load_tables.copy()

    def write_override(self, func):
        if override is None:
            raise InvalidInputException("Jumptable is not an override")

        dest_list = self.override.get_destinations()
        if len(dest_list) == 0:
            raise InvalidInputException("Jumptable has no destinations")

        program = func.get_program()
        symbol_table = program.get_symbol_table()

        namespace_space = HighFunction.find_create_override_space(func)
        if namespace_space is None:
            raise InvalidInputException("Could not create \"override\" namespace")

        space = HighFunction.find_create_namespace(symbol_table, namespace_space, "jmp_" + self.op_address.to_string())

        if not HighFunction.clear_namespace(symbol_table, space):
            raise InvalidInputException("Jumptable override namespace contains non-label symbols.")

        for i in range(len(dest_list)):
            nm = f"case_{i}"
            HighFunction.create_label_symbol(symbol_table, dest_list[i], nm, space, SourceType.USER_DEFINED, False)

    @staticmethod
    def read_override(space, symbol_table):
        branch_ind = None
        dest_list = []
        iter = symbol_table.get_symbols(space)
        while iter.has_next():
            sym = iter.next()
            if not isinstance(sym, CodeSymbol):
                continue

            addr = sym.get_address()
            if sym.name == "switch":
                branch_ind = addr
            elif sym.name.startswith("case"):
                dest_list.append(addr)

        if (branch_ind is not None) and len(dest_list) > 0:
            return JumpTable(branch_ind, dest_list, True)
        else:
            return None

class OverlayAddressSpace:
    def __init__(self):
        pass

    @property
    def is_overlay_space(self):
        # TO DO: implement this method
        pass

    def get_overlay_address(self, addr):
        # TO DO: implement this method
        pass