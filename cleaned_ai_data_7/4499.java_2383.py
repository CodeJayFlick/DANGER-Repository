class ArmAggressiveInstructionFinderAnalyzer:
    def __init__(self):
        self.name = "ARM Aggressive Instruction Finder"
        self.description = "Aggressively attempt to disassemble ARM/Thumb mixed code."
        self.cur_program = None
        self.listing = None
        self.num_instr = 0
        self.adds_info = False

    def can_analyze(self, program):
        language = program.get_language()
        return language.get_processor().equals("ARM")

    def added(self, program, set, monitor, log):
        self.cur_program = program
        self.listing = program.get_listing()

        todo_set = self.check_exec_blocks(program, set)

        tmode_reg = self.cur_program.get_program_context().get_register("TMode")
        last_body = None
        last_body_the_same_count = 0

        pseudo_disassembler = PseudoDisassembler(self.cur_program)
        # Gather up all patterns for current functions starts
        # compute_existing_masks(monitor)

        while todo_set:
            data = self.listing.get_undefined_data_at(todo_set.min_address())
            if not data:
                break

            entry = data.min_address()

            monitor.set_message("ARM AIF " + str(entry))

            if not self.do_valid_start(entry, monitor):
                return True

    def do_valid_start(self, entry, monitor):
        cur_value = None
        pseudo_context = PseudoDisassemblerContext(self.cur_program.get_program_context())

        # get the current value from the program context
        cur_value = self.cur_program.get_program_context().get_value(tmode_reg, entry, False)
        if not cur_value:
            instr = self.listing.get_instruction_before(entry)
            if instr:
                cur_value = self.cur_program.get_program_context().get_value(tmode_reg, instr.min_address(), False)

        is_valid = pseudo_disassembler.check_valid_subroutine(entry, pseudo_context, True, False)  # try the current mode

        if not is_valid and tmode_reg:
            if cur_value:
                cur_value = cur_value.flip_bit(0)
            else:
                cur_value = BigInteger.ONE
            pseudo_context.set_value(tmode_reg, entry, cur_value)

            is_valid = pseudo_disassembler.check_valid_subroutine(entry, pseudo_context, True, False)  # try the current mode

        if not is_valid:
            return False

    def check_exec_blocks(self, program, set):
        exec_set = AddressSet()
        memory_blocks = program.get_memory().get_blocks()

        for block in memory_blocks:
            if block.is_execute():
                exec_set.add_range(block.start(), block.end())

        if exec_set.empty() or not set:
            return set
        elif set.empty():
            return exec_set

        return set.intersect(exec_set)

    def schedule_follow_on_analysis(self, program, do_later_set):
        if not do_later_set.empty():
            auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
            auto_analysis_manager.schedule_one_time_analysis(self, do_later_set)


class PseudoDisassembler:
    def __init__(self, program):
        self.context = PseudoDisassemblerContext(program.get_program_context())

    def check_valid_subroutine(self, entry, pseudo_context, try_current_mode, try_previous_mode):
        # todo
        pass


class AddressSetView:
    def intersect(self, other_set):
        return self  # todo

    def subtract(self, set):
        return self  # todo

    def get_min_address(self):
        return None  # todo

    def add_range(self, start, end):
        pass  # todo
