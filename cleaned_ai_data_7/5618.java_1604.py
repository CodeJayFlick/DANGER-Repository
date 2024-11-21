class CodeXmlMgr:
    def __init__(self, program, log):
        self.program = program
        self.log = log

    # XML WRITE CURRENT DTD
    def write(self, writer, set, monitor):
        if not isinstance(set, AddressSetView):
            it = self.program.get_listing().get_instructions(True)
        else:
            it = self.program.get_listing().get_instructions(set, True)

        start_address = None
        end_address = None

        while it.has_next():
            inst = it.next()
            if start_address is None or not start_address.is_successor(inst.min_address()):
                if monitor.is_cancelled():
                    raise CancelledException()
                self.export_code_block(writer, start_address, end_address)
                start_address = inst.min_address()
            end_address = inst.max_address()

        if start_address is not None:
            self.export_code_block(writer, start_address, end_address)

    def export_code_block(self, writer, start, end):
        attrs = XmlAttributes()
        attrs.add_attribute("START", str(start))
        attrs.add_attribute("END", str(end))

        writer.start_element("CODE_BLOCK", attrs)
        writer.end_element("CODE_BLOCK")

    # XML READ CURRENT DTD
    def read(self, parser, monitor):
        set = AddressSet()

        while True:
            element = parser.next()
            if element.name == "CODE":
                break

        while element.name == "CODE_BLOCK":
            self.process_code_block(parser, element, monitor, set)
            element = parser.next()
            element = parser.next()

        disset = set.intersect(self.program.get_memory())

        if not disset.equals(set):
            self.log.append_msg("Disassembly address set changed to {}".format(disset))

        self.disassemble(dissset, monitor)

    def process_code_block(self, parser, element, monitor, set):
        start_addr_str = element.attribute["START"]
        end_addr_str = element.attribute["END"]

        if not (start_addr := XmlProgramUtilities.parse_address(start_addr_str)) or not (
            end_addr := XmlProgramUtilities.parse_address(end_addr_str)
        ):
            raise AddressFormatException("Incompatible Code Block Address Range: [{} , {} ]".format(
                start_addr, end_addr
            ))

        set.add_range(start_addr, end_addr)

    def disassemble(self, set, monitor):
        if not isinstance(set, AddressSetView):
            set = self.program.get_listing().get_addresses()

        while True:
            try:
                listing = self.program.get_listing()
                start_address = None

                for address in set:
                    if start_address is None or not start_address.is_successor(address):
                        disassembler = Disassembler(self.program, monitor, self)
                        disset = disassembler.disassemble(start_address, set)

                        if disset.empty():
                            listing.get_instruction_at(address)
                            break
                        else:
                            set.delete(dissset)
                    elif not start_address.is_successor(address):
                        break

                return
            except Exception as e:
                self.log.append_msg("Error during disassembly: {}".format(e))
