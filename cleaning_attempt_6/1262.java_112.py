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
