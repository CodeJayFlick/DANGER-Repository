class DemangledFunctionIndirect:
    def __init__(self, mangled: str, original_demangled: str):
        super().__init__(mangled, original_demangled)

    def get_type_string(self) -> str:
        return ""

    def add_function_pointer_parens(self, buffer: str, s: str) -> None:
        buffer += s
