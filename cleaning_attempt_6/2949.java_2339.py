import ghidra.app.script.GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import Undefined
from ghidra.program.model.lang import Language, Register
from ghidra.program.model.listing import Listing
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import Symbol

class BuildResultState(GhidraScript):
    def __init__(self):
        self.computed_stack_access = set()
        self.stack_element_sizes = {}
        self.stack_storage_space_id = None

    @Override
    public void run(self) throws Exception:
        func = current_program.get_function_manager().get_function_containing(current_address)
        if func is null:
            Msg.show_error(this, "Current location not contained within a function")
            return

        listing = current_program.get_listing()
        addr_factory = current_program.get_address_factory()
        ref_mgr = current_program.get_reference_manager()

        results_state = ResultsState(func.get_entry_point(), FunctionAnalyzer())

    def data_reference(self, op, instr_op_index, storage_varnode, ref_type):
        # TODO Auto-generated method stub
        Msg.info(this, "Data Ref: {} {}".format(storage_varnode, ref_type))

    def indirect_data_reference(self, op, instr_op_index, offset_varnode, size, storage_space_id, ref_type):
        # TODO Auto-generated method stub

    def resolved_flow(self, op, instr_op_index, dest_addr, current_state, results_state):
        op_addr = op.get_seqnum().get_target()
        instruction = listing.get_instruction_at(op_addr)
        if instruction is null:
            return
        conditional = instruction.get_flow_type().is_conditional()

        ref_type = None
        switch op.get_opcode():
            case PcodeOp.CALL:
                ref_type = RefType.CONDITIONAL_CALL if conditional else RefType.UNCONDITIONAL_CALL
                break
            case PcodeOp.CALLIND:
                ref_type = RefType.CONDITIONAL_COMPUTED_CALL if conditional else RefType.COMPUTED_CALL
                break
            case PcodeOp.BRANCH:
                ref_type = RefType.CONDITIONAL_JUMP if conditional else RefType.UNCONDITIONAL_JUMP
                break
            case PcodeOp.BRANCHIND:
                ref_type = RefType.CONDITIONAL_COMPUTED_JUMP if conditional else RefType.COMPUTED_JUMP
                break
            default:
                ref_type = RefType.FLOW

        instruction.add_operand_reference(instr_op_index, dest_addr, ref_type, SourceType.ANALYSIS)
        Msg.info(this, "Flow Ref: {}".format(dest_addr))
        return True

    def stack_reference(self, op, instr_op_index, stack_offset, size, storage_space_id, ref_type):
        if ref_type.is_write():
            self.stack_element_sizes[stack_space.get_address(stack_offset)] = size
            self.stack_storage_space_id = storage_space_id

    def unresolved_indirect_flow(self, op, instr_op_index, destination, current_state, results_state):
        # TODO Auto-generated method stub
        return None

    @Override
    public void run():
        results_state = MySwitchAnalyzer.analyze(current_program, func.get_entry_point())
        examined_set = results_state.get_examined_set()
        if examined_set is not null:
            tool = state.get_tool()
            if tool is not null:
                tool.fire_plugin_event(new ProgramSelectionPluginEvent("BuildResultState", new ProgramSelection(examined_set), current_program))

    def modified_registers(self):
        return sort(results_state.get_modified_registers())

    def preserved_registers(self):
        return sort(results_state.get_preserved_registers())

    def input_registers(self):
        return sort(results_state.get_input_registers())

    for candidate in results_state.get_frame_pointer_candidates():
        print("Frame-pointer candidate: {}".format(candidate))

    for seq in results_state.get_return_addresses():
        index = 0
        context_states = results_state.get_context_states(seq)
        while context_states.has_next():
            dump_stack_state(seq, ++index, context_states.next())

#    for seq in results_state.get_return_addresses():
#        index = 0
#        context_states = results_state.get_context_states(seq)
#        while context_states.has_next():
#            dump_return_state(seq, ++index, context_states.next(), reg_list)

    registers = current_program.get_language().get_registers()
    try:
        register = ask_choice("Results Query", "Select Register:", registers, null)
        while register is not null:
            first = True
            preserved = True
            varnode = Varnode(register.get_address(), register.get_minimum_byte_size())
            return_values = results_state.get_return_values(varnode)
            for value in return_values:
                if not varnode.equals(value):
                    preserved = False
                    if first:
                        first = False
                        print(register.name + " values: ")
                    print("    {}".format(value.toString(current_program.get_language())))
            register = ask_choice("Results Query", "Select Register:", registers, null)
        else:
            print(register.name + " value is preserved.")
    except CancelledException as e:
        pass

    def dump_stack_state(self, seq, index, state):
        lang = current_program.get_language()
        print("Return Stack state #{} at {}".format(index, seq))
        for op in self.computed_stack_access:
            varnode = state.get(self.stack_storage_space_id, op, op.size)
            value_str = "{}".format(varnode) if varnode is not null else "<unknown>"
            print("Stack[ {} ]: {} = {}".format(op.toString(lang), op.size, value_str))
        for addr in self.stack_element_sizes.keys():
            varnode = Varnode(addr, self.stack_element_sizes.get(addr))
            varnode_value = state.get(varnode)
            value_str = "{}".format(varnode) if varnode is not null else "<unknown>"
            print("{}: {} = {}".format(addr, varnode.size, value_str))

#    def dump_return_state(self, seq, index, state, reg_list):
#        print("Return state #{} at {}".format(index, seq))
#        for register in reg_list:
#            varnode = Varnode(register.get_address(), register.get_minimum_byte_size())
#            varnode_value = state.get(varnode)
#
    def sort(self, list):
        return sorted(list)

