class OutgoingFunctionCallNode:
    def __init__(self, program, function, source_address, filter_duplicates=False, filter_depth=0):
        super().__init__(program, function, source_address, 'FUNCTION_ICON', filter_duplicates, filter_depth)

    def recreate(self):
        return type(self)(self.program, self.function, self.source_address, self.filter_duplicates, self.filter_depth)
