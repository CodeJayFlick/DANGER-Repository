class InVmModelForLldbInterpreterTest:
    def model_host(self):
        return InVmLldbModelHost()

    @unittest.skip("Not implemented")
    def test_launch_via_interpreter_shows_in_process_container(self):
        super().testLaunchViaInterpreterShowsInProcessContainer()

    @unittest.skip("Not implemented")
    def test_attach_via_interpreter_shows_in_process_container(self):
        super().testAttachViaInterpreterShowsInProcessContainer()

    @unittest.skip("Not implemented")
    def test_execute_quit(self):
        super().testExecuteQuit()

    @unittest.skip("Not implemented")
    def test_interpreter_is_where_expected(self):
        super().testInterpreterIsWhereExpected()


if __name__ == "__main__":
    unittest.main()
