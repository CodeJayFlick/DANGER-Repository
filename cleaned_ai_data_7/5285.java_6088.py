class DemangledFunctionPointer:
    def __init__(self, mangled: str, original_demangled: str):
        super().__init__(mangled, original_demangled)
        self.increment_pointer_levels()  # a function pointer is 1 level by default

    @property
    def display_function_pointer_syntax(self) -> bool:
        return self._display_function_pointer_syntax

    @display_function_pointer_syntax.setter
    def display_function_pointer_syntax(self, value: bool):
        self._display_function_pointer_syntax = value

    def get_type_string(self) -> str:
        return "*"

    def add_function_pointer_parens(self, buffer: str, s: str) -> None:
        if not self.display_function_pointer_syntax:
            return
        buffer += f"({s})"


class AbstractDemangledFunctionDefinitionDataType:
    pass


def main():
    dfp = DemangledFunctionPointer("mangled", "original_demangled")
    print(dfp.get_type_string())  # prints "*"
