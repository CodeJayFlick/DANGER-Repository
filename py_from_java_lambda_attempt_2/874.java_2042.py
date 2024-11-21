Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Note: The Python code above uses the `unittest` module, which is a built-in testing framework in Python.