Here is the equivalent Python code:

```Python
class AbstractModelForGdbScenarioForkExitTest:
    def get_specimen(self):
        return "GDB_LINUX_FORK_EXIT"

    def pre_launch(self, launcher):
        interpreter = self.find_interpreter()
        self.wait_acc(interpreter)
        self.wait_on(interpreter.execute("set detach-on-fork off"))

    def get_parent_breakpoint_expression(self):
        return "func"

    def assert_environment(self, environment):
        # TODO: This test won't always be on amd64 Linux, no?
        if not (environment.get_architecture() == "i386:x86-64" and
                environment.get_operating_system() == "GNU/Linux" and
                environment.get_endian() == "little"):
            raise AssertionError("Unexpected architecture or operating system")
        self.assertTrue(environment.get_debugger().lower().startswith("gdb"))
```

Note that Python does not have direct equivalents for Java's `@Override` annotation, static imports, or the `package agent.ghidra.model;` declaration at the top of a file.