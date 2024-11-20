class NoFunctionGraphViewSettings(FunctionGraphViewSettings):
    def __init__(self):
        # limited usage constructor
        pass

    def __init__(self, copy_settings: FunctionGraphViewSettings):
        super().__init__(copy_settings)
