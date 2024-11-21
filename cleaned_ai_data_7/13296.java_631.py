class MipsSymbolAnalyzer:
    NAME = "MIPS Symbol"
    DESCRIPTION = "Analyze bytes for MIPS16 symbols and shift -1 as necessary."

    def __init__(self):
        # run right before the NoReturn Analyzer
        self.set_priority(AnalysisPriority.FORMAT_ANALYSIS.before().before().before().before())
        self.default_enablement(True)

    @property
    def name(self):
        return self.NAME

    @property
    def description(self):
        return self.DESCRIPTION

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog) -> bool:
        monitor.set_message("MIPS16 symbol analyzer")

        # Get ISA_MODE register
        IsaModeRegister = program.get_register("ISA_MODE")
        memory = program.get_memory()
        listing = program.get_listing()
        function_manager = program.get_function_manager()

        redo = AddressSetView()

        # Get and iterate over symbols
        symbol_table = program.get_symbol_table()
        all_symbols_iter = symbol_table.get_all_symbols(True)
        while all_symbols_iter.has_next() and not monitor.is_cancelled():
            symbol = all_symbols_iter.next()
            mem_addr = symbol.get_address()

            source_type = symbol.get_source()
            if source_type != SourceType.IMPORTED:
                continue

            # Only care if memory address
            if mem_addr.is_memory_address():
                block = memory.get_block(mem_addr)
                if block is None or not block.is_execute():
                    continue

                # Check if last bit is set to indicate MIPS16
                if (mem_addr.get_offset() & 0x01) == 0x01:
                    new_addr = mem_addr.subtract(1)

                    name = symbol.get_name()

                    # Remove symbol
                    symbol_table.remove_symbol_special(symbol)
                    function_manager.remove_function(mem_addr)
                    function_manager.remove_function(new_addr)

                    try:
                        symbol = symbol_table.create_label(new_addr, name, source_type)
                        if function_manager.has_function_at(new_addr):
                            function_manager.create_function(None, new_addr, AddressSetView([new_addr]), source_type)
                    except InvalidInputException as e:
                        pass

                    # Check if entry point
                    if symbol_table.is_external_entry_point(mem_addr) is True:
                        try:
                            symbol_table.remove_external_entry_point(mem_addr)
                            symbol_table.add_external_entry_point(new_addr)

                            program.get_program_context().set_value(IsaModeRegister, new_addr, new_addr,
                                                                   BigInteger("1"))
                            redo.add(new_addr)
                        except ContextChangeException as e:
                            print(f"Unexpected Error: {e}")

        if not redo.is_empty():
            AutoAnalysisManager.get_analysis_manager(program).re_analyze_all(redo)

        return True

    def analysis_ended(self, program):
        # After run once, set analyzer off in analyzer options
        pass

    @property
    def can_analyze(self) -> bool:
        if isinstance(program.get_language().get_processor(), Processor):
            processor = program.get_language().get_processor()
            return processor.name == "MIPS" and program.get_register("ISA_MODE") is not None
        else:
            return False

    @property
    def default_enablement(self) -> bool:
        if isinstance(program, Program):
            # Since only want this analyzer to run once, check if there are already instructions
            # if there are, return false
            if program.get_listing().get_num_instructions() != 0:
                return False

            # Otherwise, return true
            return True
        else:
            return False


class Program:
    def __init__(self):
        pass

    @property
    def language(self) -> Language:
        pass

    @property
    def memory(self) -> Memory:
        pass

    @property
    def listing(self) -> Listing:
        pass

    @property
    def function_manager(self) -> FunctionManager:
        pass

    @property
    def register(self, name: str):
        pass


class AddressSetView:
    def __init__(self):
        pass

    @property
    def is_empty(self) -> bool:
        return False

    def add(self, address: Address):
        pass

    def subtract(self, value: int):
        pass


class BigInteger(int):
    pass


class Processor:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        pass


class Register:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        pass


class MemoryBlock:
    def __init__(self):
        pass

    @property
    def is_execute(self) -> bool:
        return False


class SymbolTable:
    def __init__(self):
        pass

    @property
    def get_all_symbols(self, include_imported: bool = True):
        pass

    def remove_symbol_special(self, symbol: Symbol):
        pass

    def create_label(self, address: Address, name: str, source_type: SourceType) -> Symbol:
        pass


class FunctionManager:
    def __init__(self):
        pass

    @property
    def get_function_at(self, address: Address) -> Function:
        return None

    def remove_function(self, address: Address):
        pass

    def create_function(self, name: str = "", start_address: Address = None, body: AddressSetView = None,
                         source_type: SourceType = SourceType.IMPORTED) -> Function:
        pass


class AutoAnalysisManager:
    @staticmethod
    def get_analysis_manager(program: Program):
        return None

    @staticmethod
    def re_analyze_all(self, redo: AddressSetView):
        pass


class MessageLog:
    def __init__(self):
        pass

    def set_message(self, message: str):
        pass


class TaskMonitor:
    def __init__(self):
        pass

    def is_cancelled(self) -> bool:
        return False
