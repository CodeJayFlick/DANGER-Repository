class StartSymbol:
    def __init__(self):
        self.patexp = None

    def get_pattern_expression(self):
        return self.patexp

    def get_fixed_handle(self, hand, walker):
        hand.space = walker.get_cur_space()
        hand.offset_space = None
        hand.offset_offset = walker.get_addr().get_offset()
        hand.size = hand.space.get_pointer_size()

    def print(self, walker):
        val = walker.get_addr().get_offset()
        return "0x" + hex(val)[2:]

    def print_list(self, walker, list):
        list.append(walker.get_parent_handle())

    def restore_xml(self, parser, sleigh):
        element = parser.start("start_sym")
        self.patexp = StartInstructionValue()
        parser.end(element)
