class DexToJarExceptionHandler:
    def __init__(self):
        self.e = None

    def handle_method_translate_exception(self, method, node, visitor, e):
        self.e = e

    def handle_file_exception(self, e):
        self.e = e

    def get_file_exception(self):
        return self.e
