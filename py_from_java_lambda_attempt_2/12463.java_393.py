Here is the translation of the Java code into Python:

```Python
class InjectPayloadSleigh:
    def __init__(self):
        self.pcode_template = None
        self.param_shift = 0
        self.is_fall_thru = False
        self.incidental_copy = False
        self.input_list = []
        self.output = []
        self.sub_type = -1
        self.name = None
        self.type = -1
        self.source = ''
        self.parse_string = None

    def __init__(self, pcode_template, inject_payload_sleigh):
        self.pcode_template = pcode_template
        self.param_shift = inject_payload_sleigh.param_shift
        self.is_fall_thru = compute_fall_thru()
        self.incidental_copy = inject_payload_sleigh.incidental_copy
        self.input_list = inject_payload_sleigh.input_list.copy()
        self.output = inject_payload_sleigh.output.copy()
        self.sub_type = -1
        self.name = inject_payload_sleigh.name
        self.type = inject_payload_sleigh.type
        self.source = f"{inject_payload_sleigh.source}_FAILED"

    def __init__(self, pcode_template, tp, nm):
        self.pcode_template = pcode_template
        self.param_shift = 0
        self.is_fall_thru = compute_fall_thru()
        self.incidental_copy = False
        self.input_list = []
        self.output = []
        self.sub_type = -1
        self.name = nm
        self.type = tp
        self.source = "FAILED"
        self.parse_string = None

    def __init__(self, source_name):
        self.name = None
        self.type = -1
        self.sub_type = -1
        self.incidental_copy = False
        self.input_list = []
        self.output = []
        self.source = source_name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        self._source = value

    def set_input_parameters(self, in_list):
        self.input_list = list(in_list)

    def set_output_parameters(self, out_list):
        self.output = list(out_list)

    def get_input(self):
        return self.input_list.copy()

    def get_output(self):
        return self.output.copy()

    @property
    def is_fall_thru(self):
        return self._is_fall_thru

    @is_fall_thru.setter
    def is_fall_thru(self, value):
        self._is_fall_thru = value

    def compute_fall_thru(self):
        op_vec = self.pcode_template.get_op_vec()
        if len(op_vec) <= 0:
            return True
        switch op_vec[-1].get_opcode():
            case PcodeOp.BRANCH | PcodeOp.BRANCHIND | PcodeOp.RETURN:
                return False
        return True

    def order_parameters(self):
        id = 0
        for param in self.input_list:
            param.set_index(id)
            id += 1
        for param in self.output:
            param.set_index(id)
            id += 1

    @property
    def parse_string(self):
        return self._parse_string

    @parse_string.setter
    def parse_string(self, value):
        if value is not None and len(value) == 0:
            self._parse_string = None
        else:
            self._parse_string = value

    def release_parse_string(self):
        res = self.parse_string
        self.parse_string = None
        return res

    @property
    def pcode_template(self):
        return self._pcode_template

    @pcode_template.setter
    def pcode_template(self, value):
        self._pcode_template = value
        self.is_fall_thru = compute_fall_thru()

    def set_template(self, ctl):
        self.pcode_template = ctl
        self.is_fall_thru = compute_fall_thru()

    @property
    def incidental_copy(self):
        return self._incidental_copy

    @incidental_copy.setter
    def incidental_copy(self, value):
        self._incidental_copy = value

    def check_parameter_restrictions(self, con, addr):
        insize = len(con.input_list) if con.input_list is not None else 0
        if len(self.input_list) != insize:
            raise SleighException(f"Input parameters do not match injection specification: {self.source}")
        for i in range(len(self.input_list)):
            sz = self.input_list[i].get_size()
            if sz != 0 and sz != con.input_list[i].get_size():
                raise SleighException(
                    f"Input parameter size does not match injection specification: {self.source}"
                )
        outsize = len(con.output) if con.output is not None else 0
        if len(self.output) != outsize:
            raise SleighException(f"Output does not match injection specification: {self.source}")
        for i in range(len(self.output)):
            sz = self.output[i].get_size()
            if sz != 0 and sz != con.output[i].get_size():
                raise SleighException(
                    f"Output size does not match injection specification: {self.source}"
                )

    def setup_parameters(self, con, walker):
        self.check_parameter_restrictions(con, walker.get_addr())
        for i in range(len(self.input_list)):
            walker.allocate_operand()
            vn = con.input_list[i]
            hand = walker.get_parent_handle()
            hand.space = vn.get_address().get_address_space()
            hand.offset_offset = vn.get_offset()
            hand.size = vn.get_size()
            hand.offset_space = None
            walker.pop_operand()
        for i in range(len(self.output)):
            walker.allocate_operand()
            vn = con.output[i]
            hand = walker.get_parent_handle()
            hand.space = vn.get_address().get_address_space()
            hand.offset_offset = vn.get_offset()
            hand.size = vn.get_size()
            hand.offset_space = None
            walker.pop_operand()

    def __eq__(self, other):
        if not isinstance(other, InjectPayloadSleigh):
            return False
        if self.name != other.name:
            return False
        if len(self.input_list) != len(other.input_list):
            return False
        for i in range(len(self.input_list)):
            if self.input_list[i] != other.input_list[i]:
                return False
        if len(self.output) != len(other.output):
            return False
        for i in range(len(self.output)):
            if self.output[i] != other.output[i]:
                return False
        if self.incidental_copy != other.incidental_copy:
            return False
        # We are not comparing is_fall_thru as it's a product of the p-code templates
        if self.param_shift != other.param_shift:
            return False
        if self.type != other.type or self.sub_type != other.sub_type:
            return False
        return True

    def __hash__(self):
        hash = 79 * (1 if self.incidental_copy else 13)
        for param in self.input_list:
            hash += 79 * param.__hash__()
        for param in self.output:
            hash += 79 * param.__hash__()
        return hash
```

Please note that the above Python code is a direct translation of your Java code. It might not be perfect, as some details like error handling and edge cases are missing.