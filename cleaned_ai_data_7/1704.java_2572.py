class LldbModelTargetConnectorContainerImpl:
    def __init__(self, root):
        self.root = root
        self.default_connector = None
        
        self.process_launcher = ProcessLaunchConnector(self, "Launch process")
        self.process_launcher_ex = ProcessLaunchWithOptionsConnector(self, "Launch process w/ options")
        self.process_attacher_by_pid = ProcessAttachByPidConnector(self, "Attach to process by pid")
        self.process_attacher_by_name = ProcessAttachByNameConnector(self, "Attach to process by name")
        self.process_attacher_by_path = ProcessAttachByPathConnector(self, "Attach to process by path")
        self.trace_loader = TraceOrDumpConnector(self, "Load trace/dump")
        self.kernel_attacher = KernelConnector(self, "Attach to kernel")

    def get_default_connector(self):
        return self.default_connector

    def set_default_connector(self, default_connector):
        self.default_connector = default_connector
        self.root.set_default_connector(default_connector)


class ProcessLaunchConnector:
    def __init__(self, container, name):
        pass


class ProcessLaunchWithOptionsConnector:
    def __init__(self, container, name):
        pass


class ProcessAttachByPidConnector:
    def __init__(self, container, name):
        pass


class ProcessAttachByNameConnector:
    def __init__(self, container, name):
        pass


class ProcessAttachByPathConnector:
    def __init__(self, container, name):
        pass


class TraceOrDumpConnector:
    def __init__(self, container, name):
        pass


class KernelConnector:
    def __init__(self, container, name):
        pass
