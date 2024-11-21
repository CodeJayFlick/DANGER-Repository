class GccExceptionAnalyzer:
    NAME = "GCC Exception Handlers"
    DESCRIPTION = "Locates and annotates exception-handling infrastructure installed by the GCC compiler"

    OPTION_NAME_CREATE_TRY_CATCH_COMMENTS = "Create Try Catch Comments"
    OPTION_DESCRIPTION_CREATE_TRY_CATCH_COMMENTS = "Selecting this check box causes the analyzer to create comments in the disassembly listing for the try and catch code."
    OPTION_DEFAULT_CREATE_TRY_CATCH_COMMENTS_ENABLED = True
    create_try_catch_comments_enabled = OPTION_DEFAULT_CREATE_TRY_CATCH_COMMENTS_ENABLED

    def __init__(self):
        super().__init__(NAME, DESCRIPTION)
        self.set_default_enablement(True)
        self.set_priority(AnalysisPriority.FORMAT_ANALYSIS.after().after())

    @staticmethod
    def get_block(program: Program, name: str) -> MemoryBlock:
        return program.get_memory().get_block(name)

    @staticmethod
    def has_block(program: Program, name: str) -> bool:
        block = GccExceptionAnalyzer.get_block(program, name)
        if block is None:
            return False
        else:
            return True

    @staticmethod
    def has_arm_section(program: Program) -> bool:
        # ARM GCC exception handling support removed pending further review
        return False

    def can_analyze(self, program: Program) -> bool:
        is_gcc = program.get_compiler_spec().get_compiler_spec_id().id_as_string().lower() == "gcc"
        is_default = program.get_compiler_spec().get_compiler_spec_id().id_as_string().lower() == "default"

        if not (is_gcc or is_default):
            return False

        has_eh_frame_header = self.has_block(program, EhFrameHeaderSection.EH_FRAME_HEADER_BLOCK_NAME)
        has_eh_frame = self.has_block(program, EhFrameSection.EH_FRAME_BLOCK_NAME)
        has_debug_frame = self.has_arm_section(program)

        return (has_eh_frame or has_eh_frame_header) or has_arm_section(program) or has_debug_frame

    def added(self, program: Program, addresses: AddressSetView, monitor: TaskMonitor, log: MessageLog):
        if set([program]).issubset(visited_programs):
            return True
        else:
            auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
            auto_analysis_manager.add_listener(self.analysis_listener)

            monitor.set_message("Analyzing GCC exception- handling artifacts")
            monitor.set_indeterminate(True)
            monitor.set_show_progress_value(False)

            self.handle_standard_sections(program, monitor, log)

            # handle_arm_sections(program, monitor, log)

            visited_programs.add(program)
            monitor.set_indeterminate(False)
            monitor.set_show_progress_value(True)

    def handle_standard_sections(self, program: Program, monitor: TaskMonitor, log: MessageLog):
        fde_table_count = self.analyze_eh_frame_header_section(program, monitor, log)
        monitor.check_cancelled()

        try:
            ehframe_section = EhFrameSection(monitor, program)
            regions = ehframe_section.analyze(fde_table_count)

            for region in regions:
                monitor.check_cancelled()
                eh_protected.add(region.get_range())

                call_site_table = region.get_call_site_table()
                if call_site_table is not None:
                    for cs in call_site_table.get_call_site_records():
                        self.process_call_site_record(program, eh_protected, region, cs)
        except (MemoryAccessException, ExceptionHandlerFrameException as e):
            log.append_msg("Error analyzing GCC exception tables")
            log.append_exception(e)

    def process_call_site_record(self, program: Program, eh_protected: AddressSetView, region: RegionDescriptor, cs: LSDACallSiteRecord):
        call_site = cs.get_call_site()
        eh_protected.add(call_site)
        lp_addr = cs.get_landing_pad()

        if lp_addr is not None:
            type_infos = self.get_type_infos(region, cs)

            disassemble_if_needed(program, cs.get_address())
            if self.create_try_catch_comments_enabled:
                self.mark_start_of_try(program, call_site, lp_addr)
                self.mark_end_of_try(program, call_site)
            disassemble_if_needed(program, lp_addr)
            if self.create_try_catch_comments_enabled:
                self.mark_start_of_catch(program, cs.get_address(), lp_addr, type_infos)
                self.mark_end_of_catch(program, call_site, lp_addr)

    def get_type_infos(self, region: RegionDescriptor, cs: LSDACallSiteRecord) -> List[TypeInfo]:
        action_table = region.get_action_table()
        if action_table is None:
            return []

        action_offset = cs.get_action_offset()
        if action_offset == 0 or action_table.get_action_record_at_offset(action_offset) is None:
            return []

        type_info_address = action_table.get_type_info_address(cs.get_action_filter())
        if type_info_address is not None and cs.get_action_filter() != 0:
            return [TypeInfo(type_info_address, cs.get_action_filter())]
        else:
            return []

    def mark_start_of_try(self, program: Program, call_site: AddressRange, lp_addr: Address):
        start_try_comment = "try { // try from {} to {}".format(call_site.min_address(), call_site.max_address())
        existing_comment = program.get_listing().get_comment(CodeUnit.PRE_COMMENT, lp_addr)
        if existing_comment is None or not existing_comment.contains(start_try_comment):
            merged_comment = "{}{}".format(existing_comment, start_try_comment) if existing_comment else start_try_comment
            set_comment_cmd = SetCommentCmd(lp_addr, CodeUnit.PRE_COMMENT, merged_comment)
            set_comment_cmd.apply_to(program)

    def mark_end_of_try(self, program: Program, call_site: AddressRange):
        end_try_comment = "}"
        code_unit = program.get_listing().get_code_unit_containing(call_site.max_address())
        if code_unit is not None:
            comment_addr = code_unit.min_address()
            existing_comment = program.get_listing().get_comment(CodeUnit.POST_COMMENT, comment_addr)
            if existing_comment is None or not existing_comment.contains(end_try_comment):
                merged_comment = "{}{}".format(existing_comment, end_try_comment) if existing_comment else end_try_comment
                set_comment_cmd = SetCommentCmd(comment_addr, CodeUnit.POST_COMMENT, merged_comment)
                set_comment_cmd.apply_to(program)

    def mark_start_of_catch(self, program: Program, cs_addr: Address, lp_addr: Address, type_infos: List[TypeInfo]):
        start_catch_comment = "catch({}) {{ ... }} // from try @ {} with catch @ {}".format(", ".join([str(a) for a in type_infos]), cs_addr, lp_addr)
        existing_comment = program.get_listing().get_comment(CodeUnit.PRE_COMMENT, lp_addr)
        if existing_comment is None or not existing_comment.contains(start_catch_comment):
            merged_comment = "{}{}".format(existing_comment, start_catch_comment) if existing_comment else start_catch_comment
            set_comment_cmd = SetCommentCmd(lp_addr, CodeUnit.PRE_COMMENT, merged_comment)
            set_comment_cmd.apply_to(program)

    def mark_end_of_catch(self, program: Program, call_site: AddressRange, lp_addr: Address):
        # TODO Need to figure out way to indicate this that won't get wiped out by other analysis.
        pass

    @staticmethod
    def analyze_eh_frame_header_section(program: Program, monitor: TaskMonitor, log: MessageLog) -> int:
        try:
            ehframehdr_section = EhFrameHeaderSection(program)
            return ehframehdr_section.analyze(monitor)
        except (MemoryAccessException, ExceptionHandlerFrameException as e):
            log.append_msg("Error analyzing GCC EH Frame Header exception table")
            log.append_exception(e)

    def register_options(self, options: Options, program: Program) -> None:
        options.register_option(OPTION_NAME_CREATE_TRY_CATCH_COMMENTS, self.create_try_catch_comments_enabled,
                                 None, OPTION_DESCRIPTION_CREATE_TRY_CATCH_COMMENTS)
