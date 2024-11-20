class PefAnalyzer:
    NAME = "PEF Indirect Addressing"
    DESCRIPTION = "Creates references to symbols indirectly addresses via R2."

    def __init__(self):
        self.default_enablement = True
        self.priority = AnalysisPriority.DATA_ANALYSIS.before().before()

    @staticmethod
    def can_analyze(program: Program) -> bool:
        return program.executable_format == PefLoader.PEF_NAME

    def added(self, program: Program, function_set: AddressSetView, monitor: TaskMonitor,
               log: MessageLog):
        symbol_table = program.symbol_table
        listing = program.listing
        reference_manager = program.reference_manager
        toc_symbol = SymbolUtilities.get_expected_label_or_function_symbol(program,
                                                                           PefConstants.TOC)
        if toc_symbol is None:
            return True

        instruction_set = self.get_instruction_set(program, function_set, listing, toc_symbol, monitor)

        for instruction in listing.instructions(instruction_set):
            if monitor.is_cancelled():
                break
            operands1 = instruction.op_objects(1)
            if len(operands1) != 2 or not isinstance(operands1[0], int) or \
               not isinstance(operands1[1], str) or operands1[1] != "r2":
                continue

            scalar = operands1[0]
            register = Register(operands1[1])
            dest_addr = self.create_reference(reference_manager, toc_symbol, instruction,
                                               scalar)
            self.markup_glue_code(listing, symbol_table, instruction, dest_addr)

        return True

    def get_instruction_set(self, program: Program, function_set: AddressSetView,
                             listing: Listing, toc_symbol: Symbol, monitor: TaskMonitor) -> AddressSet:
        instruction_set = set()
        for function in listing.functions(function_set):
            try:
                program.program_context.set_register_value(function.entry_point(),
                                                            function.entry_point(), scalar)
            except ContextChangeException as e:
                pass
            instruction_set.add(function.body)

        return instruction_set

    def markup_glue_code(self, listing: Listing, symbol_table: SymbolTable,
                          instruction: Instruction, dest_addr: Address):
        operands0 = instruction.op_objects(0)
        if len(operands0) != 1 or not isinstance(operands0[0], str) or \
           operands0[0] != "r12":
            return

        mnemonic_string = instruction.mnemonic_string
        if mnemonic_string != "lwz" or dest_addr is None:
            return

        function = listing.function_containing(instruction.min_address)
        if function is None:
            return

        symbol = symbol_table.primary_symbol(dest_addr)
        if symbol is not None and not symbol.is_dynamic():
            namespace = self.get_namespace(symbol_table, PefConstants.GLUE)
            try:
                function.symbol.set_namespace(namespace)
                function.symbol.name = symbol.name
            except Exception as e:
                pass

    def create_reference(self, reference_manager: ReferenceManager,
                          toc_symbol: Symbol, instruction: Instruction, scalar: int) -> Address:
        destination_address = toc_symbol.address.add(scalar)
        reference = reference_manager.add_memory_reference(instruction.min_address(),
                                                            destination_address, RefType.READ,
                                                            SourceType.ANALYSIS, 1)
        return destination_address

    def get_namespace(self, symbol_table: SymbolTable, namespace_name: str) -> Namespace:
        try:
            namespace = symbol_table.namespace(namespace_name, None)
            if namespace is None:
                namespace = symbol_table.create_namespace(None, namespace_name,
                                                            SourceType.IMPORTED)
            return namespace
        except Exception as e:
            pass

class Register:
    def __init__(self, name: str):
        self.name = name

class AddressSet(set):
    pass

class InstructionIterator:
    def has_next(self) -> bool:
        pass

    def next(self) -> Instruction:
        pass

class MessageLog:
    def error(self, message: str, exception: Exception):
        pass
