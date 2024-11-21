class DexMarkupInstructionsAnalyzer:
    def __init__(self):
        pass

    @staticmethod
    def analyze(program: object, set: object, monitor: object, log: object) -> bool:
        if program and set:
            monitor.set_maximum(set.num_addresses())
            monitor.set_progress(0)

        analysis_state = DexAnalysisState.get_state(program)
        header = analysis_state.get_header()

        provider = MemoryByteProvider(program.memory(), program.min_address())
        reader = BinaryReader(provider, True)

        listing = program.listing

        instruction_iterator = listing.instructions(set, True)
        while instruction_iterator.has_next():
            instruction = instruction_iterator.next()
            monitor.check_canceled()
            monitor.increment_progress(1)
            monitor.set_message("DEX: Instruction markup ... " + str(instruction.min_address()))

            mnemonic_string = instruction.mnemonic_string()

            if mnemonic_string.startswith("invoke_"):
                pass
            elif mnemonic_string.startswith("const_") or mnemonic_string == "instance_of" or mnemonic_string == "check_cast":
                scalar = instruction.scalar(1)
                process_instruction(program, instruction, 1, header, int(scalar.unsigned_value()), log)

        return True

    @staticmethod
    def can_analyze(program: object) -> bool:
        provider = MemoryByteProvider(program.memory(), program.min_address())
        return DexConstants.is_dex_file(provider) or CDexConstants.is_cdex(program)
