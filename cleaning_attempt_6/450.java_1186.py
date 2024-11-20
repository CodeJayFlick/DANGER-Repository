class DebugClientImpl7(DebugClientImpl6):
    def __init__(self, jna_client: IDebugClient7):
        super().__init__(jna_client)
        self.jna_client = jna_client
