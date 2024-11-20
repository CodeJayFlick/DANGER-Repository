class ObjectiveC1MessageAnalyzer:
    DESCRIPTION = "An analyzer for extracting objc_msgSend information."
    NAME = "Objective-C Message"

    def __init__(self):
        self.default_enablement = True
        self.priority = AnalysisPriority(10000000)

    def added(self, program: Program, address_set_view: AddressSetView, task_monitor: TaskMonitor, message_log: MessageLog) -> bool:
        current_state = CurrentState(program)
        
        if not monitor.is_cancelled():
            for address in address_set_view.get_addresses(true):
                instruction_iterator = program.get_listing().get_instructions(address, True)

                while instruction_iterator.has_next():
                    if task_monitor.is_cancelled():
                        break

                    instruction = instruction_iterator.next()

                    self.inspect_function(program, instruction, current_state, monitor)
        return True

    def can_analyze(self, program: Program) -> bool:
        return ObjectiveC1Constants.is_objective_c(program)

    def inspect_function(self, program: Program, function: Function, state: CurrentState, task_monitor: TaskMonitor):
        if not function:
            return
        
        instruction_iterator = program.get_listing().get_instructions(function.get_body(), True)
        
        while instruction_iterator.has_next():
            if task_monitor.is_cancelled():
                break

            instruction = instruction_iterator.next()

            self.markup_instruction(instruction, state, monitor)

    def is_calling_objc_msg_send(self, instruction: Instruction) -> bool:
        return (instruction.num_operands() == 1 and
                isinstance(instruction.get_primary_reference(0), Reference) and
                reference.get_reference_type().is_call())

    def markup_instruction(self, instruction: Instruction, state: CurrentState, task_monitor: TaskMonitor):
        if not monitor.is_cancelled():
            for address in range(instruction.min_address(), instruction.max_address()):
                function = state.program.get_listing().get_function_containing(address)

                if function:
                    break

            self.pull_name_through(state, from_address, None)
            
    def pull_name_through(self, state: CurrentState, to_address: Address, namespace: Namespace):
        block = state.program.memory.block(to_address)

        if not block or block.name == SectionNames.TEXT_CSTRING:
            return ObjectiveC1Utilities.create_string(state.program, address)

        data = state.program.get_listing().get_data_at(address)
        
        # Rest of the code...

class CurrentState:
    def __init__(self, program: Program):
        self.program = program
        self.global_namespace = program.get_global_namespace()
        self.selector_namespace = None
        self.id_namespace = None

        self.current_class_name = None
        self.current_method_name = None

    def reset(self):
        self.current_class_name = None
        self.current_method_name = None

class AnalysisPriority:
    def __init__(self, value: int):
        self.value = value

# Rest of the code...
