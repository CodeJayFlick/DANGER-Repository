Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's static imports, so I removed the `import` statements. Also, in Python, we don't need to specify types for method parameters or return values like we do in Java.