class AssemblerBuilder:
    def __init__(self):
        pass

    def get_language_id(self) -> str:
        # TO DO: implement this method
        raise NotImplementedError("getLanguageID not implemented")

    def get_language(self) -> dict:
        # TO DO: implement this method
        raise NotImplementedError("getLanguage not implemented")

    def build_assembler(self, selector: callable, program=None) -> object:
        if program is None:
            return Assembler(selector)
        else:
            return Assembler(selector, program)

class Assembler:
    def __init__(self, selector: callable, program=None):
        self.selector = selector
        self.program = program

# Example usage:

def my_selector(code):
    # TO DO: implement this method
    pass

builder = AssemblerBuilder()
assembler1 = builder.build_assembler(my_selector)
assembler2 = builder.build_assembler(my_selector, some_program_instance)

