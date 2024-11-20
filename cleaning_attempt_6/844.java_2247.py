class AbstractModelForDbgengScenarioCloneExitTest:
    def get_specimen(self):
        return "CREATE_THREAD_EXIT"

    def get_breakpoint_expression(self):
        return "!work"
