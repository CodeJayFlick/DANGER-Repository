class DecompilerScriptUtils:
    def __init__(self, program, tool, monitor):
        self.program = program
        self.monitor = monitor
        self.tool = tool
        self.decomp_interface = self.setup_decompiler_interface()

    def setup_decompiler_interface(self):
        decomp_interface = DecompInterface()
        options = DecompileOptions()
        service = OptionsService() if self.tool else None
        opt = ToolOptions() if service else None

        if service and opt:
            options.grab_from_tool_and_program(None, opt, self.program)

        decomp_interface.set_options(options)
        decomp_interface.toggle_c_code(True)
        decomp_interface.toggle_syntax_tree(True)
        decomp_interface.set_simplification_style("decompile")

        if not decomp_interface.open_program(self.program):
            return None

        return decomp_interface

    def get_decompiler_interface(self):
        return self.decomp_interface


class HighFunction:
    pass  # This class is not implemented in the provided Java code.


def get_high_function(function, monitor=None):
    res = DecompInterface().decompile_function(function)
    if res.get_high_function() is None:
        return None
    return res.get_high_function()


def get_decompiler_return_type(function):
    decomp_res = DecompInterface().decompile_function(function)

    if decomp_res is None or decomp_res.get_high_function() is None or \
            decomp_res.get_high_function().get_function_prototype() is None:
        return None

    return decomp_res.get_high_function().get_function_prototype().get_return_type()


def get_function_signature_string(function, include_return=False):
    if function is None:
        return None
    try:
        buffer = StringBuffer()
        res = DecompInterface().decompile_function(function)
        high_function = res.get_high_function()

        if include_return:
            buffer.append(high_function.get_function_prototype().get_return_type().get_display_name() + " ")
        else:
            buffer.append("")

        buffer.append("(")

        parameter_definitions = function.get_function_prototype().get_parameter_definitions()
        for i, param in enumerate(parameter_definitions):
            monitor.check_cancelled()

            if param.name == "this":
                continue

            buffer.append(param.data_type.get_display_name() + " " + param.name)
            if i < len(parameter_definitions) - 1:
                buffer.append(", ")
            else:
                buffer.append(")")

        return buffer.toString()
    except CancelledException as e:
        raise


def get_parameters_from_decompiler(function):
    res = DecompInterface().decompile_function(function)

    if res is None or res.get_high_function() is None:
        return None

    return res.get_high_function().get_function_prototype().get_parameter_definitions()


class Address:
    def __init__(self, offset):
        self.offset = offset


def get_assigned_address_from_pcode(stored_value):
    address_offset = stored_value.offset
    if stored_value.is_constant():
        possible_address = to_addr(address_offset)
        return possible_address

    value_pcode_op = stored_value.get_def()
    if value_pcode_op.opcode == PcodeOp.CAST or value_pcode_op.opcode == PcodeOp.COPY:
        constant_varnode = value_pcode_op.input[0]
        return get_assigned_address_from_pcode(constant_varnode)

    if value_pcode_op.opcode != PcodeOp.PTRSUB:
        return None

    # don't need to check isConst bc always is
    constant_varnode = value_pcode_op.input[1]
    address_offset = constant_varnode.offset
    possible_address = to_addr(address_offset)
    if possible_address is None or not program.memory.contains(possible_address):
        return None

    return possible_address


def get_called_address_from_calling_pcode_op(pcode_op_input):
    def_ = pcode_op_input.get_def()
    if def_ is None:
        return None
    input_varnode = def_.input[1]
    if input_varnode is None:
        return None

    address = input_varnode.address
    offset = address.offset
    called_address = program.min_address.new_address(offset)
    return called_address


def to_addr(offset):
    return Address(offset)


# Usage example:

program = "path_to_your_program"
tool = "your_tool_name"

decompiler_script_utils = DecompilerScriptUtils(program, tool, None)

high_function = get_high_function(function)
print(high_function)

return_type = get_decompiler_return_type(function)
print(return_type)

signature_string = get_function_signature_string(function)
print(signature_string)

parameters = get_parameters_from_deompiler(function)
for param in parameters:
    print(param.name)

assigned_address = get_assigned_address_from_pcode(stored_value)
if assigned_address is not None:
    print(assigned_address.offset)

called_address = get_called_address_from_calling_pcode_op(pcode_op_input)
print(called_address)
