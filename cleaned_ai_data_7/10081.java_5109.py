class RMIServerPortFactory:
    REGISTERY_PORT = 0
    RMI_SSL_PORT = 1
    STREAM_PORT = 2

    def __init__(self, base_port):
        self.base_port = base_port

    def get_rmi_registry_port(self):
        return self.base_port + self.REGISTERY_PORT

    def get_rmisslport(self):
        return self.base_port + self.RMI_SSL_PORT

    def get_stream_port(self):
        return self.base_port + self.STREAM_PORT
