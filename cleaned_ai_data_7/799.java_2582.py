class DbgModelTargetConnectorContainerImpl:
    def __init__(self, root):
        self.root = root
        self.default_connector = None
        
        self.process_launcher = ProcessLaunchConnector(self, "Launch process")
        self.process_attacher = ProcessAttachConnector(self, "Attach to process")
        self.trace_loader = TraceOrDumpConnector(self, "Load trace/dump")
        self.kernel_attacher = KernelAttachConnector(self, "Attach to kernel")

    def get_default_connector(self):
        return self.default_connector

    def set_default_connector(self, default_connector):
        if isinstance(default_connector, DbgModelTargetConnector):
            self.default_connector = default_connector
            self.root.set_default_connector(default_connector)
        else:
            raise ValueError("Invalid connector type")


class ProcessLaunchConnector:
    def __init__(self, container, name):
        self.container = container
        self.name = name


class ProcessAttachConnector:
    def __init__(self, container, name):
        self.container = container
        self.name = name


class TraceOrDumpConnector:
    def __init__(self, container, name):
        self.container = container
        self.name = name


class KernelAttachConnector:
    def __init__(self, container, name):
        self.container = container
        self.name = name

