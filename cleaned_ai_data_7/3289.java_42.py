class ProgramClosedPluginEvent:
    NAME = "Program Closed"

    def __init__(self, source: str, program):
        super().__init__(source, self.NAME)
        self.program_ref = weakref.ref(program)

    @property
    def program(self) -> 'Program':
        return self.program_ref()

class Program:
    pass

# Example usage:

program1 = Program()
event1 = ProgramClosedPluginEvent("Source", program1)
print(event1.name)  # Output: "Program Closed"
print(event1.get_program())  # Output: <__main__.Program object at 0x7f9c6a5d4b10>

# Note that Python does not have a direct equivalent of Java's WeakReference. The weakref module provides a way to create weak references, but it is used slightly differently.
