class DebugControlImpl2(DebugControlImpl1):
    def __init__(self, jna_control):
        super().__init__(jna_control)
        self.jna_control = jna_control
