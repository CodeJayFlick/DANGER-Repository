Here is the translation of the Java code into Python:

```Python
class RefType:
    INVALID = 0
    FLOW = 1
    FALL_THROUGH = 2
    UNCONDITIONAL_CALL = 3
    CONDITIONAL_CALL = 4
    UNCONDITIONAL_JUMP = 5
    CONDITIONAL_JUMP = 6
    TERMINATOR = 7
    COMPUTED_CALL = 8
    COMPUTED_JUMP = 9
    CALL_OVERRIDE_UNCONDITIONAL = 10
    JUMP_OVERRIDE_UNCONDITIONAL = 11
    CALLOTHER_OVERRIDE_CALL = 12
    CALLOTHER_OVERRIDE_JUMP = 13

class FlowType:
    pass

def get_memory_ref_type(cu, op_index, to_addr):
    if isinstance(to_addr, Address) and to_addr.is_memory_address():
        block = cu.get_program().get_memory().get_block(to_addr)
        if block is not None and block.is_mapped():
            return RefType.DATA
    for result_obj in cu.get_instruction().get_result_objects():
        if result_obj == to_addr:
            return RefType.WRITE
    for input_obj in cu.get_instruction().get_input_objects():
        if input_obj == to_addr:
            if ref_type is not None and ref_type.is_write():
                return RefType.READ_WRITE
            ref_type = cu.get_operand_ref_type(op_index)
            if ref_type != RefType.INDIRECTION:
                return RefType.READ

def get_default_flow_type(instr, to_addr):
    flow_type = instr.get_flow_type()
    if isinstance(flow_type, FlowType) and not flow_type.is_terminator():
        if flow_type.is_call():
            return RefType.CONDITIONAL_CALL
        elif flow_type.is_jump():
            return RefType.CONDITIONAL_JUMP

def get_default_computed_flow_type(instr):
    for op in instr.get_pcode():
        if isinstance(op, PcodeOp) and (op.get_opcode() == PcodeOp.INT_ZEXT or op.get_opcode() == PcodeOp.COPY):
            if ref_type is not None:
                return ref_type
        elif op.get_opcode() == PcodeOp.STORE:
            if to_addr.is_memory_address() and mem_offset == op.get_input(1).get_offset():
                if ref_type is not None and ref_type.is_write():
                    return RefType.READ_WRITE
                ref_type = RefType.WRITE

def get_load_store_ref_type(ops, start_op_seq, offset_addr):
    for i in range(start_op_seq, len(ops)):
        op = ops[i]
        opcode = op.get_opcode()
        inputs = op.get_inputs()

        if opcode == PcodeOp.LOAD:
            if inputs[1].get_address().equals(offset_addr):
                if ref_type is not None and ref_type.is_write():
                    return RefType.READ_WRITE
                ref_type = RefType.READ

        elif opcode == PcodeOp.STORE:
            if inputs[1].get_address().equals(offset_addr):
                if ref_type is not None and ref_type.is_read():
                    return RefType.READ_WRITE
                ref_type = RefType.WRITE

    return ref_type

class Address:
    def __init__(self, addressable_word_offset=None):
        self.addressable_word_offset = addressable_word_offset

def get_default_jump_or_call_flow_type(instr):
    flow_type = instr.get_flow_type()
    if isinstance(flow_type, FlowType) and not flow_type.is_terminator():
        if flow_type.is_computed() and (flow_type.is_call() or flow_type.is_jump()):
            return RefType.COMPUTED_CALL
```

Please note that Python does not support Java's `static` keyword.