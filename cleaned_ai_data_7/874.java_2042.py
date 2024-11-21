class InVmModelForDbgengInterpreterTest:
    def model_host(self):
        return InVmDbgengModelHost()

    @unittest.skip("Ignore this test")
    def test_attach_via_interpreter_shows_in_process_container(self):
        super().test_attach_via_interpreter_shows_in_process_container()

    @unittest.expectedFailure
    def test_execute_quit(self):
        # Different behavior for dbg clients vice gdb

if __name__ == "__main__":
    unittest.main()
