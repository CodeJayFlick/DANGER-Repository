class DemangledLambda:
    def __init__(self, mangled: str, original_demangled: str, name: str):
        super().__init__(mangled, original_demangled, name)

    def get_namespace_name(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def add_parameters(self, buffer: str, format: bool = False) -> None:
        pass
