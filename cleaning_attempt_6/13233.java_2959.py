class BootstrapMethodsAttribute:
    def __init__(self):
        self.numberOfBootstrapMethods = 0
        self.bootstrap_methods = []

    def read_from_binary_reader(self, reader):
        super().__init__()
        self.numberOfBootstrapMethods = reader.read_short()
        for i in range(self.numberOfBootstrapMethods):
            bootstrap_method = BootstrapMethod(reader)
            self.bootstrap_methods.append(bootstrap_method)

class BootstrapMethod:
    def __init__(self, reader):
        pass

def get_number_of_bootstrap_methods(self):
    return self.numberOfBootstrapMethods & 0xffff

def get_bootstrap_methods(self):
    return self.bootstrap_methods
