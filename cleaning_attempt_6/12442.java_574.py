class CompilerSpecDescription:
    def __init__(self):
        pass

    def get_compiler_spec_id(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_compiler_spec_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_source(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")
