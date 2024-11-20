import xml.etree.ElementTree as ET
from typing import List, Tuple

class PPC64CallStubAnalyzer:
    NAME = "PPC64 ELF Call Stubs"
    DESCRIPTION = "Detect ELF Call Stubs and create thunk function"
    PROCESSOR_NAME = "PowerPC"

    CALL_STUB_PATTERN_FILE = "ppc64-elf-call-stubs.xml"

    UNKNOWN_FUNCTION_NAME = "_unknown_call_stub_"

    pattern_load_failed: bool
    be_call_stub_patterns: List[Tuple[int, int]]
    le_call_stub_patterns: List[Tuple[int, int]]
    max_pattern_length: int

    def __init__(self):
        super().__init__()
        self.default_enablement = True
        self.priority = AnalysisPriority.FUNCTION_ANALYSIS.before()

    @staticmethod
    def can_analyze(program) -> bool:
        language = program.language()
        if PROCESSOR_NAME == language.processor().name and \
           language.size() == 64 and patterns_loaded(language.is_big_endian()):
            r2_reg = program.register("r2")
            ctr_reg = program.register("CTR")
            return r2_reg is not None and ctr_reg is not None
        return False

    @staticmethod
    def patterns_loaded(big_endian: bool) -> bool:
        if PPC64CallStubAnalyzer.pattern_load_failed:
            return False
        try:
            pattern_file = Application.get_module_data_file(PPC64CallStubAnalyzer.CALL_STUB_PATTERN_FILE)
            be_call_stub_patterns = []
            ET.parse(pattern_file, lambda x: [be_call_stub_patterns.extend([int(i) for i in str(x).split(",")])])
            max_pattern_length = 0
            for pattern in be_call_stub_patterns:
                len_ = pattern[1]
                if (len_ % 4 != 0):
                    raise SAXException("pattern must contain multiple of 4-bytes")
                if len_ > PPC64CallStubAnalyzer.max_pattern_length:
                    PPC64CallStubAnalyzer.max_pattern_length = len_
        except FileNotFoundError as e:
            Msg.error(PPC64CallStubAnalyzer, "PowerPC resource file not found: " + PPC64CallStubAnalyzer.CALL_STUB_PATTERN_FILE)
            PPC64CallStubAnalyzer.pattern_load_failed = True
            return False
        except (SAXException, IOException) as e:
            Msg.error(PPC64CallStubAnalyzer, "Failed to parse byte pattern file: " + PPC64CallStubAnalyzer.CALL_STUB_PATTERN_FILE, e)
            PPC64CallStubAnalyzer.pattern_load_failed = True
            return False
        return True

    @staticmethod
    def flip_patterns(pattern_list) -> List[Tuple[int, int]]:
        flipped_pattern_list = []
        for pattern in pattern_list:
            bytes_ = [i.to_bytes(1, 'big') for i in range(int.from_bytes(pattern[0], 'big'))]
            mask = [i.to_bytes(1, 'big') for i in range(int.from_bytes(pattern[1], 'big'))]
            new_pattern = (b''.join(bytes_), b''.join(mask))
            flipped_pattern_list.append(new_pattern)
        return flipped_pattern_list

    @staticmethod
    def flip_pattern_bytes(byte_array) -> bytes:
        result = bytearray(len(byte_array))
        for i in range(0, len(byte_array), 4):
            byte = byte_array[i]
            result[i] = byte[3]
            result[i + 1] = byte[2]
            result[i + 2] = byte[1]
            result[i + 3] = byte[0]
        return bytes(result)

    def added(self, program: Program, address_set_view: AddressSetView, task_monitor: TaskMonitor, message_log: MessageLog) -> bool:
        memory = program.memory()
        listing = program.listing()
        program_context = program.program_context()

        sequence_search_state = SequenceSearchState.build_state(program.memory().is_big_endian(), be_call_stub_patterns)

        monitor.set_indeterminate(False)
        monitor.set_maximum(address_set_view.num_addresses())
        monitor.set_progress(0)
        function_count = 0

        for function in listing.get_functions(address_set_view, True):
            if task_monitor.check_cancelled():
                return False
            monitor.set_progress(function_count + 1)

            entry_addr = function.entry_point()
            is_thunk = function.is_thunk()

            stub_match = None
            if not is_thunk:
                stub_match = self.match_known_call_stubs(entry_addr, memory, sequence_search_state)
                if stub_match is None:
                    continue

            register_value = program_context.get_register_value(self.r2_reg, entry_addr)

            if register_value is None or not register_value.has_value():
                if not is_thunk:
                    # Thunk unknown function for future processing once r2 is propagated
                    self.create_thunk(program, entry_addr, stub_match[1], self.unknown_function_name)
                continue

            analyze_call_stub(self, program, function, len(stub_match), monitor)

    def match_known_call_stubs(self, addr: Address, memory: Memory, sequence_search_state) -> Tuple[int]:
        bytes_ = bytearray(PPC64CallStubAnalyzer.max_pattern_length)
        matches = []

        try:
            cnt = memory.get_bytes(addr, bytes_)
        except MemoryAccessException as e:
            pass

        if cnt == 0:
            return None
        elif cnt != len(bytes_):
            # although rare, shorten searchBytes if unable to fill
            search_bytes = bytearray(cnt)
            for i in range(len(bytes_) - 1, -1, -1):
                System.arraycopy(bytes_, i, search_bytes, i - cnt + 1, 4)

        matches.clear()
        sequence_search_state.apply(search_bytes, matches)
        if len(matches) == 0:
            return None

        return (addr.get_new_address(int.from_bytes(search_bytes[:4], 'big')), int.from_bytes(search_bytes[4:], 'big'))

    def create_thunk(self, program: Program, addr: Address, length: int, thunked_function_addr):
        stub_body = AddressSet(addr, addr.add(length - 1))
        cmd = CreateThunkFunctionCmd(addr, stub_body, thunked_function_addr)
        cmd.apply_to(program)

    def analyze_call_stub(self, program: Program, function: Function, length: int, monitor) -> None:
        sym_eval = SymbolicPropogator(program)
        eval = ContextEvaluatorAdapter()

        entry_addr = function.entry_point()
        stub_body = AddressSet(entry_addr, entry_addr.add(length - 1))

        context_evaluator = self.ContextEvaluatorAdapter()
        if not context_evaluator.follow_false_conditional_branches():
            return

    def get_unknown_function(self, program: Program) -> Function:
        try:
            return program.external_manager().add_ext_function(Library.UNKNOWN, UNKNOWN_FUNCTION_NAME, None, SourceType.IMPORTED).get_function()
        except (InvalidInputException, DuplicateNameException as e):
            raise AssertException("unexpected", e)

    def thunks_unknown_function(self, function: Function) -> bool:
        thunked_function = function.get_thunked_function(False)
        if thunked_function is None or not thunked_function.is_external():
            return False
        return UNKNOWN_FUNCTION_NAME == thunked_function.name

    def create_destination_function(self, program: Program, addr: Address, flow_from_addr: Address, reg_value: RegisterValue, monitor) -> Function:
        listing = program.listing()
        bookmark_mgr = program.bookmark_manager()

        if not program.memory().contains(addr):
            bookmark_mgr.set_bookmark(flow_from_addr, BookmarkType.ERROR, "Bad Reference", f"No memory for call stub destination at {addr}")
            return None

        function = listing.get_function_at(addr)

        if reg_value is not None and reg_value.has_value():
            program_context = program.program_context()
            old_value = program_context.get_register_value(reg_value.register(), addr)
            if old_value is None or not old_value.has_value():
                try:
                    program_context.set_register_value(addr, addr, reg_value)
                except ContextChangeException as e:
                    raise AssertException(e)

        return function
