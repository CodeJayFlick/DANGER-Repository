class AnalyzeAllOpenProgramsTask:
    def __init__(self, plugin):
        self.prototype_program = None
        self.programs = []
        self.tool = plugin.get_tool()
        program_manager = tool.get_service(ProgramManager)
        self.prototype_program = program_manager.get_current_program()
        self.programs = list(program_manager.get_all_open_programs())

    def run(self, monitor):
        if not self.programs:
            return
        monitor.initialize(len(self.programs))
        valid_programs = None
        analysis_options = None
        options = tool.get_options(GhidraOptions.CATEGORY_AUTO_ANALYSIS)
        show_dialog = options.get_boolean("Show Analysis Options", True)
        if show_dialog:
            try:
                valid_programs = self.check_for_invalid_programs_by_architecture()
            except CancelledException as e:
                return

            auto_analysis_manager = AutoAnalysisManager(self.prototype_program)
            if not set_options(self.prototype_program, auto_analysis_manager):
                return
            analysis_options = AnalysisOptions(self.prototype_program)

        else:
            valid_programs = self.programs[:]

        self.analyze_programs(analysis_options, valid_programs, monitor)

    def analyze_programs(self, analysis_options, valid_programs, monitor):
        bottom_up_cancelled_listener = None
        top_down_cancelled_listener = None

        for i in range(len(valid_programs)):
            if monitor.is_cancelled():
                break

            program = valid_programs[i]
            if not program.is_closed():
                continue

            monitor.set_message("Analyzing " + program.get_name() + "...")

            id = program.start_transaction("analysis")
            try:
                auto_analysis_manager = AutoAnalysisManager(program)
                self.initialize_analysis_options(program, analysis_options, auto_analysis_manager)

                GhidraProgramUtilities.set_analyzed_flag(program, True)

                analyze_strategy.analyze_program(program, auto_analysis_manager, monitor)
            finally:
                program.end_transaction(id, True)

        if monitor.is_cancelled():
            for program in self.programs:
                AutoAnalysisManager.get_analysis_manager(program).cancel_queued_tasks()

    def initialize_analysis_options(self, program, analysis_options, manager):
        if not analysis_options:
            return False

        program_id = ProgramID(program)
        if not program_id.equals(analysis_options.get_program_id()):
            return False

        manager.initialize_options(analysis_options.get_analysis_options_property_list())
        return True

    def set_options(self, program, manager):
        atomic_boolean = AtomicBoolean()
        id = program.start_transaction("analysis")
        try:
            Swing.run_now(lambda: OptionDialog.show(None, "Show Analysis Options", "Continue",
                OptionDialog.WARNING_MESSAGE, None))
        finally:
            program.end_transaction(id, True)

    def get_valid_programs_by_architecture(self):
        valid_list = self.programs[:]
        for program in self.programs:
            if not ProgramID(program).equals(ProgramID(self.prototype_program)):
                valid_list.remove(program)
        return valid_list

    def check_for_invalid_programs_by_architecture(self) -> list[Program]:
        valid_list = self.get_valid_programs_by_architecture()
        if len(valid_list) != len(self.programs):
            invalid_list = [program for program in self.programs if not ProgramID(program).equals(ProgramID(self.prototype_program))]
            return show_non_matching_architectures_warning(valid_list, invalid_list)
        return valid_list

    def show_non_matching_architectures_warning(self, valid_list: list[Program], invalid_list: list[Program]) -> list[Program]:
        buffy = "<html><BR>"
        buffy += "Found open programs with architectures differing from the current program.<BR><BR><BR>"

        buffy += "These programs <B>will</B> be analyzed:<BR><BR>"
        buffy += "<TABLE BORDER=\"0\" CELLPADDING=\"5\">"
        self.append_table_header(buffy)

        for i, program in enumerate(valid_list):
            if not program == self.prototype_program:
                special_font_open = ""
                special_font_close = ""

            buffy += f"<TR><TD>{special_font_open}{HTMLUtilities.escape_html(program.get_name())}{special_font_close}</TD>"
            buffy += "<TD>" + str(program.get_language_id())
            buffy += "</TD><TD>" + program.get_compiler_spec().get_compiler_spec_id() + "</TD></TR>"

        buffy += f"<TR><TD COLSPAN=\"3\"><BR><BR>These programs will <B>not</B> be analyzed:<BR><BR></TD></TR>"
        self.append_table_header(buffy)

        for program in invalid_list:
            buffy += f"<TR><TD>{HTMLUtilities.escape_html(program.get_name())}</TD><TD>" + str(
                program.get_language_id())
            buffy += "</TD><TD>" + program.get_compiler_spec().get_compiler_spec_id() + "</TD></TR>"

        buffy += "</TABLE>"
        return Swing.run_now(lambda: OptionDialog.show(None, buffy, "Continue", OptionDialog.WARNING_MESSAGE, None))

    def append_table_header(self, buffy):
        buffy += "<TR><TH ALIGN=\"left\"><U>Name</U></TH>"
        buffy += f"<TH ALIGN=\"left\"><U>{self.prototype_program.get_name()}</U></TH>"
        buffy += "</TR>"

class ProgramID:
    def __init__(self, program):
        self.language_id = program.get_language_id()
        self.compiler_spec_id = program.get_compiler_spec().get_compiler_spec_id()

    def equals(self, other):
        if not isinstance(other, ProgramID):
            return False

        return (isinstance(self.language_id, str) and isinstance(other.language_id, str)
                and self.language_id == other.language_id
                and isinstance(self.compiler_spec_id, CompilerSpecID) and isinstance(other.compiler_spec_id, CompilerSpecID)
                and self.compiler_spec_id.equals(other.compiler_spec_id))

    def get_program_id(self):
        return (self.language_id, self.compiler_spec_id)

class AnalysisOptions:
    def __init__(self, program):
        self.options = program.get_options(Program.ANALYSIS_PROPERTIES)
        self.program_id = ProgramID(program)

    def get_program_id(self):
        return self.program_id

    def get_analysis_options_property_list(self):
        return self.options
