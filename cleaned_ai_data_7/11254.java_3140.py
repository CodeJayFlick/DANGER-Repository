class ServiceInterfaceImplementationPair:
    def __init__(self, interface_class: type, provider):
        self.interface_class = interface_class
        self.provider = provider
