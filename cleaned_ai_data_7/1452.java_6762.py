class AbstractGdbModelHost:
    def get_factory_options(self):
        return {
            "GDB launch command": GdbManager.DEFAULT_GDB_CMD,
        }
