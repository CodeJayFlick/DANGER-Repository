class DbgModelTargetExceptionImpl:
    COMMAND_ATTRIBUTE_NAME = "Command"
    COMMAND2_ATTRIBUTE_NAME = "SecondCmd"
    CONTINUE_OPTION_ATTRIBUTE_NAME = "Continue"
    EXECUTE_OPTION_ATTRIBUTE_NAME = "Execute"
    EXCEPTION_CODE_ATTRIBUTE_NAME = "Exception"

    def __init__(self, exceptions: 'DbgModelTargetExceptionContainer', filter: 'DbgExceptionFilter'):
        super().__init__()
        self.filter = filter
        self.exec_option = None
        self.cont_option = None

        exec_option = DebugFilterExecutionOption.get_by_number(filter.execution_option)
        cont_option = DebugFilterContinuationOption.get_by_number(filter.continue_option)

        self.exec_option = DbgModelTargetExecutionOptionImpl(self, exec_option)
        self.cont_option = DbgModelTargetContinuationOptionImpl(self, cont_option)

        attributes = {
            DISPLAY_ATTRIBUTE_NAME: filter.index,
            COMMAND_ATTRIBUTE_NAME: filter.cmd,
            COMMAND2_ATTRIBUTE_NAME: filter.cmd,
            EXECUTE_OPTION_ATTRIBUTE_NAME: self.exec_option,
            CONTINUE_OPTION_ATTRIBUTE_NAME: self.cont_option,
            EXCEPTION_CODE_ATTRIBUTE_NAME: filter.exception_code
        }
        super().change_attributes([], [], attributes, "Initialized")

    def get_filter(self):
        return self.filter

    def get_event_index(self):
        return self.filter.index

    def event_selected(self, event: 'AbstractDbgEvent', cause: 'DbgCause'):
        if isinstance(event, DbgExceptionEvent):
            info = event.info
            if info.code == int(filter.exception_code, 16):
                focus_scope = search_for_suitable(TargetFocusScope)
                focus_scope.set_focus(self)

    def get_configurable_options(self) -> dict:
        configurable_options = {}
        cmd_desc = ParameterDescription(String, COMMAND_ATTRIBUTE_NAME, False, "", COMMAND_ATTRIBUTE_NAME, "filter command")
        configurable_options[COMMAND_ATTRIBUTE_NAME] = cmd_desc
        cmd_desc2 = ParameterDescription(String, COMMAND2_ATTRIBUTE_NAME, False, "", COMMAND2_ATTRIBUTE_NAME, "filter 2nd-chance command")
        configurable_options[COMMAND2_ATTRIBUTE_NAME] = cmd_desc2
        exec_desc = ParameterDescription(Integer, EXECUTE_OPTION_ATTRIBUTE_NAME, False, self.exec_option.option(), EXECUTE_OPTION_ATTRIBUTE_NAME, "filter execution option")
        configurable_options[EXECUTE_OPTION_ATTRIBUTE_NAME] = exec_desc
        cont_desc = ParameterDescription(Integer, CONTINUE_OPTION_ATTRIBUTE_NAME, False, self.cont_option.option(), CONTINUE_OPTION_ATTRIBUTE_NAME, "filter continuation option")
        configurable_options[CONTINUE_OPTION_ATTRIBUTE_NAME] = cont_desc

    def write_configuration_option(self, key: str, value):
        if key == COMMAND_ATTRIBUTE_NAME:
            # code for writing command attribute
        elif key == COMMAND2_ATTRIBUTE_NAME:
            # code for writing 2nd-chance command attribute
        elif key == EXECUTE_OPTION_ATTRIBUTE_NAME:
            self.exec_option.set_option(value)
        elif key == CONTINUE_OPTION_ATTRIBUTE_NAME:
            self.cont_option.set_option(value)

