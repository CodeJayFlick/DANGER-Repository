class SleighAssembler:
    def __init__(self):
        pass  # TODO: Implement this method.

    @staticmethod
    def patch_program(res, at) -> InstructionIterator:
        if not res.get_instruction().is_full_mask():
            raise AssemblySelectionError("Selected instruction must have a full mask.")
        return patch_program(res.get_instruction().get_vals(), at)

    @staticmethod
    def assemble(at: Address, assembly: str):
        start = at
        buf = bytearray()
        for line in assembly.split("\n"):
            rv = program.get_disassembly_context(at)
            ctx = AssemblyPatternBlock.from_register_value(rv).fill_mask()
            insbytes = assemble_line(at, line, ctx)
            if insbytes is None:
                return None
            try:
                buf.extend(insbytes)
            except Exception as e:
                raise AssertionError(e)
            at += len(insbytes)
        return patch_program(buf.tobytes(), start)

    @staticmethod
    def assemble_line(at: Address, line: str) -> bytearray:
        ctx = default_context.get_default_at(at).fill_mask()
        return assemble_line(at, line, ctx)

    @staticmethod
    def parse_line(line: str):
        return parser.parse(line, get_program_labels())

    @staticmethod
    def resolve_tree(parse_result: AssemblyParseResult, at: Address) -> AssemblyResolutionResults:
        if not parse_result.is_error():
            raise AssemblySyntaxError("Parsing error")
        ctx = default_context.get_default_at(at).fill_mask()
        return resolve_tree(parse_result, at, ctx)

    @staticmethod
    def resolve_line(at: Address, line: str):
        return resolve_line(at, line, get_program_labels())

    @staticmethod
    def assemble_line(at: Address, line: str) -> bytearray:
        if not lang.get_context_base_register().get_minimum_byte_size() <= len(line):
            raise AssemblyError("Context must be fully-specified (full length, no shift, no unknowns)")
        parse_results = parser.parse(line)
        results = []
        for p in parse_results:
            results.append(resolve_tree(p, at))
        return assemble_line(at, line)

    @staticmethod
    def get_program_labels():
        labels = {}
        for reg in lang.get_registers():
            if not "register".equals(reg.get_address_space().get_name()):
                labels[reg.get_name()] = reg.get_offset()
        program_symbols = program.get_symbol_table().get_all_symbols(False)
        while program_symbols.has_next():
            symbol = program_symbols.next()
            if symbol.is_external():
                continue
            label = {}
            for sym in program_symbols:
                if not "register".equals(reg.get_address_space().get_name()):
                    labels[reg.get_name()] = reg.get_offset()
        return labels

    @staticmethod
    def get_context_at(addr: Address):
        rv = program.get_disassembly_context(addr)
        return AssemblyPatternBlock.from_register_value(rv)

class InstructionIterator:
    pass  # TODO: Implement this class.

class AssemblyParseResult:
    pass  # TODO: Implement this class.

class AssemblyResolutionResults:
    pass  # TODO: Implement this class.
