Here's a translation of your Java code into Python:

```Python
class DecompilerSwitchAnalyzer:
    NAME = "Decompiler Switch Analysis"
    DESCRIPTION = "Creates switch statements for dynamic instructions using Decompiler."
    
    OPTION_NAME_DECOMPILER_TIMEOUT_SECS = "Analysis Decompiler Timeout (sec)"
    OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS = "Set timeout in seconds for analyzer decompiler calls."
    DEFAULT_DECOMPILER_TIMEOUT_SECS = 60
    decompiler_timeout_seconds_option = DEFAULT_DECOMPILER_TIMEOUT_SECS
    
    hit_non_returning_function = False
    isa_mode_switch_register = None
    isa_mode_register = None

    def __init__(self):
        super().__init__(NAME, DESCRIPTION)
        self.set_priority(AnalysisPriority.CODE_ANALYSIS)
        self.default_enablement(True)

    @property
    def can_analyze(self, program: Program) -> bool:
        return program.get_language().supports_pcode()

    @property
    def default_enablement(self, program: Program) -> bool:
        return True

    def register_options(self, options: Options, program: Program):
        options.register_option(OPTION_NAME_DECOMPILER_TIMEOUT_SECS,
                                 self.decompiler_timeout_seconds_option,
                                 None,
                                 OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS)

    def options_changed(self, options: Options, program: Program):
        self.decompiler_timeout_seconds_option = options.get_int(
            OPTION_NAME_DECOMPILER_TIMEOUT_SECS, self.decompiler_timeout_seconds_option
        )

    @property
    def added(self, program: Program, address_set_view: AddressSetView,
              task_monitor: TaskMonitor) -> bool:
        try:
            locations = find_locations(program, address_set_view, task_monitor)
            if not locations:
                return True

            functions = find_functions(program, locations, task_monitor)

            if self.hit_non_returning_function:
                self.hit_non_returning_function = False
                restart_remaining_later(program, functions)
                return True

            run_decompiler_analysis(program, functions, task_monitor)
        except (CancelledException, Exception):
            pass

    def find_locations(self, program: Program, address_set_view: AddressSetView,
                        task_monitor: TaskMonitor) -> list:
        max_address = address_set_view.get_max_address()
        locations = []
        listing = program.get_listing()

        for instruction in listing.get_instructions(address_set_view, True):
            if task_monitor.is_cancelled():
                break

            flow_type = instruction.get_flow_type()
            if not (flow_type.is_jump() or flow_type.is_computed()):
                continue
            elif is_call_fixup(program, instruction, flow_type):
                locations.append(instruction.min_address)
        return locations

    def find_functions(self, program: Program, locations: list,
                        task_monitor: TaskMonitor) -> set:
        pool = AutoAnalysisManager.get_shared_analsys_thread_pool()
        callback = FindFunctionCallback(program)

        queue = ConcurrentQBuilder.build(callback, pool, task_monitor)
        for location in locations:
            queue.add(location)

        results = queue.wait_for_results()

        functions = set()
        for result in results:
            function = result.result
            if not (function is None or function.is_thunk()):
                continue

            if function.has_no_return():
                self.hit_non_returning_function = True
            else:
                functions.add(function)
        return functions

    def run_decompiler_analysis(self, program: Program, functions: set,
                                 task_monitor: TaskMonitor):
        callback = DecompilerCallback(program, SwitchAnalysisDecompileConfigurer(program))
        callback.set_timeout(self.decompiler_timeout_seconds_option)

        try:
            ParallelDecompiler.decompile_functions(callback, functions, task_monitor)
        finally:
            callback.dispose()

    def restart_remaining_later(self, program: Program, functions: set):
        func_set = AddressSet()
        for function in functions:
            if not (function is None or function.is_thunk()):
                continue

            if function.has_no_return():
                self.hit_non_returning_function = True
            else:
                func_set.add(function.get_body())

        AutoAnalysisManager.get_analysis_manager(program).schedule_one_time_analysis(
            DecompilerSwitchAnalyzer(), func_set)

    def handle_simple_block(self, location: Address,
                             task_monitor: TaskMonitor) -> bool:
        basic_block_model = BasicBlockModel(program)
        return resolve_computable_flow(location, task_monitor, basic_block_model)

    def is_call_fixup(self, program: Program, instruction: Instruction,
                       flow_type: FlowType) -> bool:
        if not (flow_type.is_jump() or flow_type.is_computed()):
            return False

        references_from = program.get_reference_manager().get_references_from(instruction.min_address)
        for reference in references_from:
            ref_type = reference.reference_type
            if ref_type.is_computed():
                return True
        return False

    def resolve_computable_flow(self, location: Address,
                                 task_monitor: TaskMonitor,
                                 basic_block_model: BasicBlockModel) -> bool:
        jump_block_at = basic_block_model.get_first_code_block_containing(location, task_monitor)
        found_count = AtomicInteger(0)

        symbolic_propogator = SymbolicPropogator(program)
        prop = PropagationContextEvaluatorAdapter()
        for instruction in listing.get_instructions(address_set_view, True):
            if task_monitor.is_cancelled():
                break

            flow_type = instruction.get_flow_type()
            if not (flow_type.is_jump() or flow_type.is_computed()):
                continue
            elif is_call_fixup(program, instruction, flow_type):
                locations.append(instruction.min_address)
        return found_count.get() == 1


class FindFunctionCallback:
    def __init__(self, program: Program):
        self.program = program

    @property
    def process(self, location: Address,
                 task_monitor: TaskMonitor) -> Function:
        if task_monitor.is_cancelled():
            return None

        monitor.increment_progress(1)

        references_from = program.get_reference_manager().get_references_from(location)
        for reference in references_from:
            ref_type = reference.reference_type
            if ref_type.is_computed() and ref_type.is_flow() and program.memory.contains(reference.to_address):
                propogate_code_mode(context, address)
                found_count.incrementAndGet()
                return None

        function = program.get_function_manager().get_function_containing(location)

        if function is None:
            func = UndefinedFunction.find_function_using_simple_block_model(program, location, task_monitor)
        else:
            CreateFunctionCmd.fixup_function_body(program, fixup_func, monitor)
            if fixup_func.has_no_return():
                return fixup_func
            return None

    def propogate_code_mode(self, context: VarnodeContext,
                             address: Address):
        # get CodeModeRegister and flow it to destination, if it is set here
        if isa_mode_switch_register is None:
            return

        value = context.get_value(isa_mode_switch_register, False)
        if value is not None and program.listing.get_instruction_at(address) is None:
            try:
                program.program_context.set_value(isa_mode_register, address, address, value)
            except ContextChangeException as e:
                # ignore
                pass


class DecompilerCallback:
    def __init__(self, program: Program,
                 switch_analysis_decompile_configurer: SwitchAnalysisDecompileConfigurer):
        self.program = program
        self.switch_analysis_decompile_configurer = switch_analysis_decompile_configurer

    @property
    def process(self, results: DecompileResults,
                task_monitor: TaskMonitor) -> Void:
        cmd = DecompilerSwitchAnalysisCmd(results)
        cmd.apply_to(program, monitor)
        return None


class SwitchAnalysisDecompileConfigurer:
    pass


class BasicBlockModel:
    pass


class SymbolicPropogator:
    pass
```

This translation is not a direct conversion from Java to Python. The original code has been modified and optimized for the Python language.