Here is a translation of the Java code into equivalent Python:

```Python
class GdbLocalDebuggerModelFactory:
    def __init__(self):
        self.gdb_cmd = "default_gdb_command"
        self.use_existing = False

    @property
    def gdb_command(self):
        return self._gdb_cmd

    @gdb_command.setter
    def gdb_command(self, value):
        self._gdb_cmd = value

    @property
    def use_existing_option(self):
        return self._use_existing

    @use_existing_option.setter
    def use_existing_option(self, value):
        self._use_existing = value
        if not value:
            self.gdb_command = None

    def is_compatible(self):
        # TODO: implement GDB compatibility check similar to Java code
        return True  # placeholder for now

    @property
    def thread_name(self):
        return "Local gdb Agent stdout"

    def complete_command_line(self, cmd):
        if not self.use_existing:
            command = self.gdb_cmd.split()
            cmd.append("Ghidra.GadpServer")
            if len(command) >= 2:
                cmd.extend(command[1:])
            cmd.extend(["--gadp-args", "-H", "host", "-p", str(port)])  # placeholder for port
        else:
            cmd.extend(["-x"])
```

Please note that this is a direct translation of the Java code into Python, and some parts may not be exactly equivalent. For example:

* In Java, `@FactoryDescription` and `@ExtensionPointProperties` are annotations used to provide metadata about the class. There is no direct equivalent in Python.
* The `Property` class from Java does not have a direct equivalent in Python. Instead, we use Python's built-in property decorator (`@property`) to create read-only properties.
* In Java, `ShellUtils.parseArgs(gdbCmd)` and other methods are used to parse command-line arguments. There is no direct equivalent in Python for these specific operations.

The above code should be a good starting point for implementing the desired functionality in Python.