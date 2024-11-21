class DBTraceProgramViewReferenceManager:
    def __init__(self, program):
        super().__init__(program)

    def get_reference_operations(self, create_if_absent=False):
        return self.program.trace.get_reference_manager()

    def get_code_operations(self, create_if_absent=False):
        return self.program.trace.get_code_manager()
