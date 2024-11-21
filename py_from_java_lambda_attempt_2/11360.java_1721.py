Here is the translation of the Java interface `AssemblerBuilder` to a Python class:

```python
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

```

Note that I've used Python's built-in `callable` type to represent the selector callback. In Java, you would use an interface or a functional interface for this purpose.

Also note that I haven't implemented any of the methods in the original code; these are just placeholders until you fill them with your actual implementation logic.