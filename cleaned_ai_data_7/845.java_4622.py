class AbstractModelForDbgengScenarioForkExitTest:
    def get_specimen(self):
        return "CREATE_PROCESS"

    def get_parent_breakpoint_expression(self):
        return "expCreateProcess!func"

    def get_child_breakpoint_expression(self):
        return "expCreateProcess!func"

    def assert_environment(self, environment):
        self.assertEqual("x86_64", environment["architecture"])
        self.assertEqual("Windows", environment["operating_system"])
        self.assertEqual("little", environment["endian"])
        self.assertTrue(environment["debugger"].lower().find("dbgeng") != -1)
