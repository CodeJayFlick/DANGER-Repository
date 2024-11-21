class SH4EarlyAddressAnalyzer:
    def __init__(self):
        self.set_priority("DISASSEMBLY")

    def flow_constants(self, program: 'Program', flow_start: int, 
                       flow_set: set[int], sym_eval: 'SymbolicPropogator', monitor: 'TaskMonitor') -> set[int]:
        # follow all flows building up context
        # use context to fill out addresses on certain instructions

        class ContextEvaluator:
            def evaluate_reference(self, context: dict, instr: int, pcodeop: int, 
                                    address: int, size: int, ref_type: str) -> bool:
                if ref_type == "flow":
                    if self.is_call(instr):
                        # set the called function to have a constant value for this register
                        propagate_r12_to_call(program, context, address)
                    return False

                elif ref_type == "computed":
                    do_ref = super().evaluate_reference(context, instr, pcodeop, 
                                                         address, size, ref_type)
                    if not do_ref:
                        return False
                    if check_computed_relative_branch(program, monitor, instr, address, 
                                                      ref_type, pcodeop):
                        return False
                    return do_ref

                # in the Early analyzer, don't lay down anything other than computed call references
                return False

        eval = ContextEvaluator()
        result_set = sym_eval.flow_constants(flow_start, None, eval, True, monitor)
        return result_set


class Program:
    pass


class SymbolicPropogator:
    def flow_constants(self, start: int, end=None, context_evaluator=None, 
                       propagate_constant=False, task_monitor=None) -> set[int]:
        # implementation of this method is not provided
        pass


def propagate_r12_to_call(program: 'Program', context: dict, address: int):
    # implementation of this function is not provided
    pass


def check_computed_relative_branch(program: 'Program', monitor: 'TaskMonitor', 
                                    instr: int, address: int, ref_type: str, pcodeop: int) -> bool:
    # implementation of this function is not provided
    pass

