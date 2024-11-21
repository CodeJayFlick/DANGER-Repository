class PdbErrorHandler:
    def __init__(self):
        self.log = None

    def set_log(self, log):
        self.log = log

    def error(self, exception):
        if self.log:
            print(f"PDB XML Error: {exception}")

    def fatalError(self, exception):
        if self.log:
            print(f"PDB XML FatalError: {exception}")

    def warning(self, exception):
        if self.log:
            print(f"PDB XML Warning: {exception}")
