import os

class InVmGdbModelHost:
    def get_model_factory(self):
        if not os.access('/usr/bin/gdb', os.X_OK):
            raise AssertionError("GDB cannot be found")
        return GdbInJvmDebuggerModelFactory()
