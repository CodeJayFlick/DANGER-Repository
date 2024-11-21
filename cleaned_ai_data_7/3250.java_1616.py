class AddShiftedMemRefCmd:
    def __init__(self, from_addr, to_addr, ref_type, source, op_index, shift):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.ref_type = ref_type
        self.source = source
        self.op_index = op_index
        self.shift = shift

    def apply_to(self, obj):
        p = Program(obj)
        ref_mgr = p.get_reference_manager()
        ref_mgr.add_shifted_mem_reference(from_addr=self.from_addr,
                                           to_addr=self.to_addr,
                                           shift=self.shift,
                                           ref_type=self.ref_type,
                                           source=self.source,
                                           op_index=self.op_index)
        return True

    def get_status_msg(self):
        return ""

    def get_name(self):
        return "Add Shifted Memory Reference"
