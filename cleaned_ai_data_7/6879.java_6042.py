class DecompilerFunctionAnalyzer:
    NAME = "Decompiler Parameter ID"
    DESCRIPTION = ("Creates parameter and local variables for a Function using Decompiler." 
                   "\n" 
                   "WARNING: This can take a SIGNIFICANT Amount of Time!\n" 
                   "         Turned off by default for large programs\n" 
                   "You can run this later using \"Analysis->Decompiler Parameter ID\"")

    MEDIUM_SIZE_PROGRAM = 2 * 1024 * 1024

    ENABLED_PROPERTY = "DecompilerParameterAnalyzer.enabled"
    OPTION_NAME_CLEAR_LEVEL = "Analysis Clear Level"
    OPTION_NAME_COMMIT_DATA_TYPES = "Commit Data Types"
    OPTION_NAME_COMMIT_VOID_RETURN = "Commit Void Return Values"
    OPTION_NAME_DECOMPILER_TIMEOUT_SECS = "Analysis Decompiler Timeout (sec)"

    OPTION_DESCRIPTION_CLEAR_LEVEL = "Set level for amount of existing parameter data to clear"
    OPTION_DESCRIPTION_COMMIT_DATA_TYPES = "Turn on to commit data types"
    OPTION_DESCRIPTION_COMMIT_VOID_RETURN = "Turn on to lock in 'void' return values"
    OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS = "Set timeout in seconds for analyzer decompiler calls."

    DEFAULT_CLEAR_LEVEL = SourceType.ANALYSIS
    DEFAULT_COMMIT_DATA_TYPES = True
    DEFAULT_COMMIT_VOID_RETURN = False
    DEFAULT Decompiler TIMEOUT SECONDS = 60

    def __init__(self):
        super().__init__(NAME, DESCRIPTION)
        self.set_priority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after())
        self.supports_one_time_analysis()

    @property
    def source_type_clear_level_option(self):
        return self._source_type_clear_level_option

    @source_type_clear_level_option.setter
    def source_type_clear_level_option(self, value):
        self._source_type_clear_level_option = value

    @property
    def commit_data_types_option(self):
        return self._commit_data_types_option

    @commit_data_types_option.setter
    def commit_data_types_option(self, value):
        self._commit_data_types_option = value

    @property
    def commit_void_return_option(self):
        return self._commit_void_return_option

    @commit_void_return_option.setter
    def commit_void_return_option(self, value):
        self._commit_void_return_option = value

    @property
    def decompiler_timeout_seconds_option(self):
        return self._decompiler_timeout_seconds_option

    @decompiler_timeout_seconds_option.setter
    def decompiler_timeout_seconds_option(self, value):
        self._decompiler_timeout_seconds_option = value

    def added(self, program: Program, address_set_view: AddressSetView, task_monitor: TaskMonitor, message_log: MessageLog) -> bool:
        cmd = DecompilerParameterIdCmd(NAME, address_set_view,
                                        source_type_clear_level_option,
                                        commit_data_types_option,
                                        commit_void_return_option,
                                        decompiler_timeout_seconds_option)
        cmd.apply_to(program, task_monitor)
        return True

    def can_analyze(self, program: Program) -> bool:
        return program.get_language().supports_pcode()

    def get_default_enablement(self, program: Program) -> bool:
        if is_disabled_from_property():
            return False
        num_addr = program.get_memory().get_num_addresses()
        # only do for windows by default, windows has good type info
        return (num_addr < MEDIUM_SIZE_PROGRAM) and PeLoader.PE_NAME.equals(program.get_executable_format())

    def is_disabled_from_property(self):
        default_enabled_property = System.getProperty(ENABLED_PROPERTY)
        if default_enabled_property == None:
            return False

        enabled = Boolean.parseBoolean(default_enabled_property)
        return not enabled

    def register_options(self, options: Options, program: Program) -> None:
        help_location = HelpLocation("AutoAnalysisPlugin", "Decompiler_Parameter_ID_Analyzer")

        options.register_option(OPTION_NAME_CLEAR_LEVEL, DEFAULT_CLEAR_LEVEL, help_location,
                                 OPTION_DESCRIPTION_CLEAR_LEVEL)

        options.register_option(OPTION_NAME_COMMIT_DATA_TYPES, commit_data_types_option, help_location,
                                 OPTION_DESCRIPTION_COMMIT_DATA_TYPES)

        options.register_option(OPTION_NAME_COMMIT_VOID_RETURN, commit_void_return_option, help_location,
                                 OPTION_DESCRIPTION_COMMIT_VOID_RETURN)

        options.register_option(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompiler_timeout_seconds_option,
                                help_location, OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS)
