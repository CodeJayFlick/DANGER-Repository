Here is the translation of the Java code into Python:

```Python
class PcodeFormatter:
    def __init__(self):
        self.EOL = "\n"
        self.max_display_lines = 0
        self.display_raw_pcode = False
        self.metrics = None
        self.address_color = (255, 0, 0)
        self.register_color = (128, 64, 0)
        self.scalar_color = (192, 192, 192)
        self.local_color = (0, 0, 128)

    def set_options(self, max_display_lines, display_raw_pcode):
        self.max_display_lines = max_display_lines
        self.display_raw_pcode = display_raw_pcode

    def set_font_metrics(self, metrics):
        self.metrics = metrics

    def setColor(self, address_color, register_color, scalar_color, local_color):
        self.address_color = address_color
        self.register_color = register_color
        self.scalar_color = scalar_color
        self.local_color = local_color

    def format_op_tpl(self, program, op, indent=False):
        line_list = []
        if has_label([op]):
            line_list.append(AttributedString("  ", (0, 255, 0), self.metrics))
            line_list.append(AttributedString("  ", (0, 255, 0), self.metrics))

        output_tpl = op.get_output()
        if output_tpl is not None:
            format_varnode_tpl(program, -1, -1, output_tpl, line_list)

        for i in range(len(op.get_input())):
            input = op.get_input()[i]
            if i > 0:
                line_list.append(AttributedString(",", (255, 0, 0), self.metrics))
            line_list.append(AttributedString(" ", (128, 64, 0), self.metrics))

        opcode = op.get_opcode()
        if PcodeOp.PTRADD == opcode:
            label = "<" + str(op.get_input()[0].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics))
            return CompositeAttributedString(line_list)

        for i in range(len(op.get_output())):
            output = op.get_output()[i]
            if i > 0:
                line_list.append(AttributedString(",", (128, 64, 0), self.metrics))

        format_varnode_tpl(program, opcode, -1, op.get_input(), line_list)

    def to_attributed_strings(self, program, pcode_ops):
        return [self.format_op_tpl(program, op) for op in pcode_ops]

class AttributedString:
    def __init__(self, text, color, metrics):
        self.text = text
        self.color = color
        self.metrics = metrics

class CompositeAttributedString(list):
    pass

def format_varnode_tpl(self, program, opcode, i, vTpl, line_list):
    space = vTpl.get_space()
    offset = vTpl.get_offset()
    size = vTpl.get_size()

    if space.is_const_space():
        if offset.type == ConstTpl.REAL:
            line_list.append(AttributedString(" 0x" + str(long(offset.real)), (255, 0, 0), self.metrics))
        else:
            line_list.append(AttributedString("$U" + str(long(offset.real)), (128, 64, 0), self.metrics))

    elif space.is_unique_space():
        if offset.type == ConstTpl.REAL and size.type == ConstTpl.REAL:
            line_list.append(AttributedString("inst_start", (255, 0, 0), self.metrics))
        else:
            line_list.append(AttributedString("$U" + str(long(offset.real)), (128, 64, 0), self.metrics))

    elif space.is_address_space():
        if offset.type == ConstTpl.REAL and size.type == ConstTpl.J_CURSPACE_SIZE:
            line_list.append(AttributedString("inst_start", (255, 0, 0), self.metrics))
        else:
            line_list.append(AttributedString("$U" + str(long(offset.real)), (128, 64, 0), self.metrics))

    return

def format_size(self, size, line_list):
    if size.type == ConstTpl.REAL and size.real != 0:
        line_list.append(AttributedString(":", (255, 0, 0), self.metrics))
        line_list.append(AttributedString(str(long(size.real)), (128, 64, 0), self.metrics))

def format_address(self, program, addr_space, offset, size, line_list):
    if addr_space is None:
        line_list.append(AttributedString("*", (255, 0, 0), self.metrics))
        line_list.append(AttributedString("0x" + str(long(offset.real)), (128, 64, 0), self.metrics))

    else:
        line_list.append(AttributedString("$U" + str(long(offset.real)), (128, 64, 0), self.metrics)
        if size.type == ConstTpl.J_CURSPACE_SIZE and size.real != 0:
            line_list.append(AttributedString(":", (255, 0, 0), self.metrics))
            line_list.append(AttributedString(str(long(size.real)), (128, 64, 0), self.metrics))

def format_constant(self, offset, size, line_list):
    if offset.type == ConstTpl.REAL:
        line_list.append(AttributedString("0x" + str(long(offset.real)), (255, 0, 0), self.metrics))
    else:
        line_list.append(AttributedString("$U" + str(long(offset.real)), (128, 64, 0), self.metrics)

def format_unique(self, offset, size, line_list):
    if offset.type == ConstTpl.REAL and size.type == ConstTpl.REAL:
        line_list.append(AttributedString("inst_start", (255, 0, 0), self.metrics))
    else:
        line_list.append(AttributedString("$U" + str(long(offset.real)), (128, 64, 0), self.metrics)

def format_memory_input(self, program, input0, input1, line_list):
    if not input0.is_const_space() or input0.offset.type != ConstTpl.REAL:
        raise ValueError("Expected constant input[0] for LOAD/STORE pcode op")

    id = int(input0.offset.real)
    addr_space = program.get_address_factory().get_address_space(id)

    line_list.append(AttributedString(addr_space.name, (255, 0, 0), self.metrics))
    line_list.append(AttributedString("(", (128, 64, 0), self.metrics))

def format_call_other_name(self, language, input0, line_list):
    if not input0.is_const_space() or input0.offset.type != ConstTpl.REAL:
        raise ValueError("Expected constant input[0] for CALLOTHER pcode op")

    id = int(input0.offset.real)
    psuedo_op = ((SleighLanguage) language).get_user_defined_op_name(id)

    if psuedo_op is None:
        Msg.error(PcodeFormatter, "Psuedo-op index not found: " + str(id))
        psuedo_op = "unknown"

    line_list.append(AttributedString('"', (255, 0, 0), self.metrics))
    line_list.append(AttributedString(psuedo_op, (128, 64, 0), self.metrics))
    line_list.append(AttributedString'"', (255, 0, 0), self.metrics)

def has_label(self, pcode_ops):
    for op in pcode_ops:
        if PcodeOp.PTRADD == op.get_opcode():
            return True
    return False

class ConstTpl:
    REAL = "REAL"
    J_CURSPACE_SIZE = "J_CURSPACE_SIZE"

class VarnodeTpl:
    def __init__(self, space, offset, size):
        self.space = space
        self.offset = offset
        self.size = size

def get_varnode_tpl(self, program, v):
    return VarnodeTpl(program.get_address_factory().get_address_space(v.space), v.offset, v.size)

class OpTpl:
    def __init__(self, opcode, output, inputs):
        self.opcode = opcode
        self.output = output
        self.inputs = inputs

def get_label_op_template(self, addr_factory, label_index):
    offset_tpl = ConstTpl(REAL, label_index)
    space_tpl = ConstTpl(addr_factory.get_constant_space())
    size_tpl = ConstTpl(REAL, 8)

    return OpTpl(PcodeOp.PTRADD, None, [VarnodeTpl(space_tpl, offset_tpl, size_tpl)])

def get_pcode_op_templates(self, addr_factory, pcode_ops):
    list = []
    for op in pcode_ops:
        output_tpl = op.get_output()
        if output_tpl is not None:
            format_varnode_tpl(program, -1, -1, output_tpl, line_list)

        for i in range(len(op.get_input())):
            input = op.get_input()[i]
            if i > 0:
                line_list.append(AttributedString(",", (255, 0, 0), self.metrics))

        opcode = op.get_opcode()
        if PcodeOp.PTRADD == opcode:
            label = "<" + str(op.get_input()[0].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics))
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics))
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics))
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics))
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics))
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode_ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops)):
        op = pcode.ops[i]
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255, 0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops[i]):
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255,0, 0), self.metrics)
            return CompositeAttributedString(line_list)

    for i in range(len(pcode_ops[i]):
        if PcodeOp.PTRADD == op.get_opcode():
            label = "<" + str(op.get_input()[i].get_offset()) + ">"
            line_list.append(AttributedString(label, (255,0, 0), self.metrics
            return CompositeAttributedString(line_list)

   