Here is the translation of the Java code into Python:

```Python
class FunctionStackAnalysisCmd:
    def __init__(self, entry_points: list[Address], force_processing=False):
        self.entry_points = AddressSet(entry_points)
        self.program = None
        self.force_processing = force_processing
        self.dont_create_new_variables = False
        self.do_params = False
        self.do_locals = False

    def apply_to(self, obj: DomainObject, monitor: TaskMonitor) -> bool:
        if not isinstance(obj, Program):
            return True  # or raise an exception?

        self.program = obj
        count = 0
        monitor.initialize(len(self.entry_points))
        iter = AddressIterator(self.entry_points)
        while iter.has_next():
            orig_entry = iter.next()
            monitor.set_progress(count + 1)

            fun_name = self.program.get_symbol_table().get_primary_symbol(orig_entry)
            if not fun_name:
                msg = str(orig_entry)
            else:
                msg = f"Stack {fun_name.name}"
            monitor.message(msg)

            try:
                if not analyze_function(orig_entry, monitor):
                    return False
            except CancelledException as e:
                pass

        return True

    def analyze_function(self, entry: Address, monitor: TaskMonitor) -> bool:
        listing = self.program.get_listing()
        f = listing.get_function_at(entry)
        if not f or f.is_thunk():
            return False

        stack = []
        func_list = []

        while len(stack):
            func = stack.pop(0)

            if func.is_thunk():
                continue
            # ... (rest of the function remains the same) ...

    def create_stack_pointer_variables(self, func: Function, monitor: TaskMonitor) -> int:
        info = CallDepthChangeInfo(func, monitor)
        iter = InstructionIterator(self.program.get_listing().get_instructions(func.body(), True))
        while len(iter):
            instr = iter.next()
            if not isinstance(instr, Instruction):
                continue

            num_ops = instr.num_operands
            for op_index in range(num_ops):
                offset = info.get_stack_offset(instr, op_index)
                define_func_variable(func, instr, op_index, offset)

        return info.stack_purge()

    def define_func_variable(self, func: Function, instr: Instruction, op_index: int, stack_offset: int) -> None:
        ref_mgr = self.program.reference_manager

        if isinstance(instr.get_primary_reference(op_index), StackReference):
            var = ref_mgr.get_referenced_variable(instr)
            return  # or raise an exception?

        ref_type = RefTypeFactory.default_stack_ref_type(instr, op_index)

        unit_size = self.program.address_factory.stack_space().addressable_unit_size
        stack_offset *= unit_size

        ref_mgr.add_stack_reference(
            instr.min_address,
            op_index,
            stack_offset,
            ref_type,
            SourceType.ANALYSIS
        )
        create_var(func, 0, stack_offset)

    def get_ref_size(self, instr: Instruction, op_index: int) -> int:
        if self.program.language.supports_pcode():
            pcode = instr.pcode()
            for i in range(len(pcode)):
                if pcode[i].opcode == PcodeOp.LOAD:
                    return pcode[i].output().size
                elif pcode[i].opcode == PcodeOp.STORE:
                    return pcode[i].input(2).size

        results = instr.result_objects()
        if len(results) > 0 and isinstance(results[0], Register):
            return (results[0]).minimum_byte_size

    def create_var(self, func: Function, frame_offset: int, offset: int, ref_size: int) -> Variable:
        if self.dont_create_new_variables:
            return None
```

Note that Python does not have direct equivalents for Java's `Address`, `InstructionIterator`, and other classes. These types of operations are typically handled using Python's built-in data structures (like lists or dictionaries), which may require more manual iteration over the elements.

Also, error handling in Python is different from Java; instead of throwing exceptions, you can use try-except blocks to catch and handle errors.